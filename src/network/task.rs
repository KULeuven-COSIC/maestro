use std::{
    borrow::Borrow,
    cell::OnceCell,
    collections::{BTreeMap, VecDeque},
    fmt::Debug,
    io::{self, ErrorKind, Read, Write},
    sync::{
        mpsc::{channel, sync_channel, Receiver, RecvError, Sender, SyncSender, TryRecvError},
        Mutex,
    },
    thread::{self, JoinHandle},
};

use crate::{party::CombinedCommStats, share::Field};
use itertools::Itertools;
use lazy_static::lazy_static;

#[cfg(feature = "verbose-timing")]
use {crate::party::Timer, std::time::Instant};

use super::{non_blocking::NonBlockingCommChannel, receiver, CommChannel};

#[derive(Copy, Clone, Debug)]
pub enum Direction {
    Next,
    Previous,
}

pub enum Task {
    Write {
        thread_id: Option<u64>,
        data: Vec<u8>,
    },
    Read {
        thread_id: Option<u64>,
        length: usize,
        mailback: oneshot::Sender<Vec<u8>>,
    },
    Sync {
        /// if true, write comm stats to IO_COMM_STATS and reset the stats
        write_comm_stats: bool,
    },
}

struct ReadTask {
    buffer: Vec<u8>,
    length: usize,
    offset: usize,
    mailback: oneshot::Sender<Vec<u8>>,
}

impl ReadTask {
    pub fn new(length: usize, mailback: oneshot::Sender<Vec<u8>>) -> Self {
        Self {
            buffer: vec![0u8; length],
            length,
            offset: 0,
            mailback,
        }
    }
}

struct WriteTask {
    /// thread_id and thread_id_offset
    thread_id: Option<([u8; U64_BYTE_SIZE], usize)>,
    buffer: Vec<u8>,
    offset: usize,
}

impl WriteTask {
    pub fn new(thread_id: Option<u64>, buffer: Vec<u8>) -> Self {
        Self {
            thread_id: thread_id.map(|id| (id.to_le_bytes(), 0)),
            buffer,
            offset: 0,
        }
    }
}

struct TaskQueue<T> {
    queue: VecDeque<T>,
    queue_thread_id: BTreeMap<u64, VecDeque<T>>,
    el_count: usize,
}

impl<T> TaskQueue<T> {
    pub fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            queue_thread_id: BTreeMap::new(),
            el_count: 0,
            // queue_next: VecDeque::new(),
            // queue_prev: VecDeque::new(),
        }
    }

    pub fn put(&mut self, id: Option<u64>, t: T) {
        match id {
            Some(id) => self.put_with_thread_id(id, t),
            None => {
                self.queue.push_back(t);
                self.el_count += 1;
            }
        }
    }

    fn put_with_thread_id(&mut self, id: u64, t: T) {
        let mut queue = self.queue_thread_id.get_mut(&id);
        if queue.is_none() {
            self.queue_thread_id.insert(id, VecDeque::new());
            queue = self.queue_thread_id.get_mut(&id);
        }
        if let Some(queue) = queue {
            queue.push_back(t);
            self.el_count += 1;
        }
    }

    pub fn pop(&mut self) -> Option<T> {
        let popped = self.queue.pop_front();
        if popped.is_some() {
            // we actually removed an element
            self.el_count -= 1;
        }
        popped
    }

    pub fn pop_with_thread_id(&mut self, id: u64) -> Option<T> {
        self.queue_thread_id.get_mut(&id).and_then(|q| {
            let popped = q.pop_front();
            if popped.is_some() {
                // we actually removed an element
                self.el_count -= 1;
            }
            popped
        })
    }

    pub fn peek(&mut self) -> Option<&mut T> {
        self.queue.front_mut()
    }

    pub fn peek_or_peek_from_any_thread_id(&mut self) -> Option<&mut T> {
        if !self.queue.is_empty() {
            self.queue.front_mut()
        } else {
            // pick any element from queue_thread_id
            if let Some(mut entry) = self.queue_thread_id.first_entry() {
                let queue = entry.get_mut();
                let next_element = queue.pop_front().unwrap();
                if queue.is_empty() {
                    entry.remove_entry();
                }
                self.queue.push_back(next_element);
                self.queue.front_mut()
            } else {
                None
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.el_count == 0
    }
}

impl Debug for Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Task::Read {
                thread_id, length, ..
            } => write!(f, "Read({:?}, len={})", thread_id, length),
            Task::Write { thread_id, data } => {
                write!(f, "Write({:?}, len={})", thread_id, data.len())
            }
            Task::Sync { .. } => write!(f, "Sync"),
        }
    }
}

impl Debug for ReadTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Read(offset={}, len={})", self.offset, self.length)
    }
}

impl<T: Debug> Debug for TaskQueue<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let queue = self
            .queue
            .iter()
            .map(|task| format!("{:?}", task))
            .join(", ");
        let queue_threadid = self
            .queue_thread_id
            .iter()
            .map(|(id, queue)| {
                let queue = queue.iter().map(|task| format!("{:?}", task)).join(", ");
                format!("key={}, queue=[{}]", id, queue)
            })
            .join(", ");
        write!(
            f,
            "TaskQueue: queue=[{}], queue_thread_id=[{}]",
            queue, queue_threadid
        )
    }
}

enum State {
    WaitingForTasks,
    Working {
        sync_requested: bool,
        close_requested: bool,
        write_comm_stats_requested: bool,
    },
    Sync {
        close_requested: bool,
        write_comm_stats: bool,
    },
    Close,
}

impl State {
    pub fn is_working(&self) -> bool {
        matches!(self, Self::Working { .. })
    }
}

struct IoThreadContext {
    comm: NonBlockingCommChannel,
    read_tasks_receiver: Receiver<Task>,
    read_queue: TaskQueue<ReadTask>,
    write_queue: TaskQueue<WriteTask>,
    sync: SyncSender<()>,
    state: State,
}

const U64_BYTE_SIZE: usize = (u64::BITS / 8) as usize;

impl IoThreadContext {
    pub fn new(
        comm: CommChannel,
        task_channel: Receiver<Task>,
    ) -> io::Result<(Self, Receiver<()>)> {
        let (send, receive) = sync_channel(0); // bound 0 creates rendez-vouz channel
        Ok((
            Self {
                comm: NonBlockingCommChannel::from_channel(comm)?,
                read_tasks_receiver: task_channel,
                read_queue: TaskQueue::new(),
                write_queue: TaskQueue::new(),
                sync: send,
                state: State::WaitingForTasks,
            },
            receive,
        ))
    }

    fn handle_io(&mut self, my_direction: Direction) -> io::Result<()> {
        let mut thread_id_buf = [0u8; U64_BYTE_SIZE];
        let mut thread_id_buf_offset = 0;
        loop {
            match self.state {
                State::WaitingForTasks => {
                    // wait for new tasks, this blocks
                    match self.read_tasks_receiver.recv() {
                        Ok(task) => {
                            self.add_task(task); // this changes state
                            if self.state.is_working() {
                                // try to write
                                if !self.write_queue.is_empty() {
                                    Self::non_blocking_write(
                                        &mut self.comm,
                                        &mut self.write_queue,
                                    )?;
                                }
                                // try to read
                                if !self.read_queue.is_empty() {
                                    Self::non_blocking_read(
                                        &mut self.comm,
                                        &mut self.read_queue,
                                        &mut thread_id_buf,
                                        &mut thread_id_buf_offset,
                                    )?;
                                }
                                if self.write_queue.is_empty()
                                    && self.read_queue.is_empty()
                                    && !self.comm.stream.wants_write()
                                {
                                    self.state = State::WaitingForTasks; // the added task was small enough to be completed right away
                                }
                            }
                        }
                        Err(RecvError) => {
                            // the sender disconnected, this indicates closing
                            self.state = State::Close;
                        }
                    }
                }
                State::Working {
                    sync_requested,
                    close_requested,
                    write_comm_stats_requested,
                } => {
                    if self.read_queue.is_empty()
                        && self.write_queue.is_empty()
                        && !self.comm.stream.wants_write()
                    {
                        self.state = if sync_requested {
                            State::Sync {
                                close_requested,
                                write_comm_stats: write_comm_stats_requested,
                            }
                        } else if close_requested {
                            State::Close
                        } else {
                            // nothing to do, wait for new tasks
                            State::WaitingForTasks
                        };
                    } else {
                        // there is work to do
                        if !self.write_queue.is_empty() {
                            Self::non_blocking_write(&mut self.comm, &mut self.write_queue)?;
                        }
                        if !self.read_queue.is_empty() {
                            Self::non_blocking_read(
                                &mut self.comm,
                                &mut self.read_queue,
                                &mut thread_id_buf,
                                &mut thread_id_buf_offset,
                            )?;
                        }
                        if self.comm.stream.wants_write() {
                            Self::non_blocking_write_tls(&mut self.comm)?;
                        }

                        // let's see if new tasks are available
                        self.add_new_tasks_non_blocking();
                    }
                }
                State::Sync {
                    close_requested,
                    write_comm_stats,
                } => {
                    if write_comm_stats {
                        // write and reset the communication statistics
                        let stats = self.comm.get_comm_stats();
                        self.comm.reset_comm_stats();
                        let mut guard = IO_COMM_STATS.lock().unwrap();
                        match my_direction {
                            Direction::Next => guard.next = stats,
                            Direction::Previous => guard.prev = stats,
                        }
                        drop(guard);
                    }

                    // the protocol wants to sync and all tasks are done
                    match self.sync.send(()) {
                        Ok(()) => {
                            self.state = if close_requested {
                                State::Close // sync took place, close
                            } else {
                                State::WaitingForTasks // sync took place, wait for new tasks
                            };
                        }
                        Err(_) => panic!("The receiver for the sync channel was dropped."),
                    }
                }
                State::Close => {
                    // graceful closing
                    debug_assert!(self.read_queue.is_empty() && self.write_queue.is_empty());
                    return Ok(());
                }
            }
        }
    }

    fn add_task(&mut self, task: Task) {
        match task {
            Task::Read {
                thread_id,
                length,
                mailback,
            } => {
                self.read_queue
                    .put(thread_id, ReadTask::new(length, mailback));
                if !self.state.is_working() {
                    self.state = State::Working {
                        sync_requested: false,
                        close_requested: false,
                        write_comm_stats_requested: false,
                    }
                }
            }

            Task::Write { thread_id, data } => {
                self.write_queue
                    .put(thread_id, WriteTask::new(thread_id, data));
                if !self.state.is_working() {
                    self.state = State::Working {
                        sync_requested: false,
                        close_requested: false,
                        write_comm_stats_requested: false,
                    }
                }
            }

            Task::Sync { write_comm_stats } => {
                if let State::Working {
                    close_requested,
                    write_comm_stats_requested,
                    ..
                } = self.state
                {
                    // there are tasks left that will be completed before sync
                    self.state = State::Working {
                        sync_requested: true,
                        close_requested,
                        write_comm_stats_requested: write_comm_stats | write_comm_stats_requested,
                    };
                } else {
                    self.state = State::Sync {
                        close_requested: false,
                        write_comm_stats,
                    };
                }
            }
        }
    }

    fn add_new_tasks_non_blocking(&mut self) {
        let mut cont = true;
        while cont && self.state.is_working() {
            match self.read_tasks_receiver.try_recv() {
                Ok(task) => {
                    self.add_task(task);
                }
                Err(TryRecvError::Empty) => cont = false,
                Err(TryRecvError::Disconnected) => {
                    // the sender disconnected, this indicates closing
                    cont = false;
                    if let State::Working {
                        sync_requested,
                        write_comm_stats_requested,
                        ..
                    } = self.state
                    {
                        self.state = State::Working {
                            sync_requested,
                            close_requested: true,
                            write_comm_stats_requested,
                        }
                    }
                }
            }
        }
    }

    fn non_blocking_read(
        channel: &mut NonBlockingCommChannel,
        read_task_queue: &mut TaskQueue<ReadTask>,
        thread_id_buf: &mut [u8; U64_BYTE_SIZE],
        thread_id_buf_offset: &mut usize,
    ) -> io::Result<()> {
        match read_task_queue.peek() {
            Some(read_task) => {
                let buf = &mut read_task.buffer[read_task.offset..];
                match channel.stream.read(buf) {
                    Ok(n) => {
                        read_task.offset += n;
                        if read_task.offset >= read_task.length {
                            // task is done
                            let t = read_task_queue.pop().unwrap(); // this should not panic since we peeked before
                            channel.bytes_received += t.length as u64;
                            channel.rounds += 1;
                            // send the result back
                            t.mailback
                                .send(t.buffer)
                                .expect("Cannot send read result back; receiver was dropped.");
                        }
                        Ok(())
                    }
                    Err(io_err) => {
                        // a few error types are expected, and are not an error
                        if io_err.kind() == ErrorKind::WouldBlock
                            || io_err.kind() == ErrorKind::Interrupted
                        {
                            return Ok(()); // all is well, we try again later
                        }
                        Err(io_err)
                    }
                }
            }
            None => {
                // the current problem with the implementation for multi-threaded communication via one IoLayer is
                // that reads with thread_id == Some(id) need to be declared BEFORE we read data from the network
                // since we read id* from the network and if the read task for id* has not yet been declared (i.e. because the thread is a bit late)
                // then we don't know how long that message is, so we cannot continue reading (and buffer the message for id* somewhere to pick up later)
                // and thus we have to stall the reading until that thread declares a read task for id*
                if !read_task_queue.is_empty() {
                    if *thread_id_buf_offset < thread_id_buf.len() {
                        // there are read tasks with thread_id but none are currently being read
                        match channel
                            .stream
                            .read(&mut thread_id_buf[*thread_id_buf_offset..])
                        {
                            Ok(n) => *thread_id_buf_offset += n,
                            Err(io_err) => {
                                // a few error types are expected, and are not an error
                                if io_err.kind() == ErrorKind::WouldBlock
                                    || io_err.kind() == ErrorKind::Interrupted
                                {
                                    return Ok(()); // all is well, we try again later
                                }
                                return Err(io_err);
                            }
                        }
                    }
                    if *thread_id_buf_offset >= thread_id_buf.len() {
                        // grab relevant read task
                        // check if the appropriate read task is present
                        let t =
                            read_task_queue.pop_with_thread_id(u64::from_le_bytes(*thread_id_buf));
                        if let Some(task) = t {
                            // completed reading the id
                            *thread_id_buf_offset = 0;
                            read_task_queue.put(None, task);
                        }
                    }
                    Ok(())
                } else {
                    // no read task, nothing to do
                    Ok(())
                }
            }
        }
    }

    fn non_blocking_write(
        channel: &mut NonBlockingCommChannel,
        write_task_queue: &mut TaskQueue<WriteTask>,
    ) -> io::Result<()> {
        match write_task_queue.peek_or_peek_from_any_thread_id() {
            Some(write_task) => {
                if write_task.offset == 0 {
                    if let Some((id, offset)) = &mut write_task.thread_id {
                        if *offset < U64_BYTE_SIZE {
                            match channel.stream.write(&id[*offset..]) {
                                Ok(n) => *offset += n,
                                Err(io_err) => {
                                    // a few error types are expected, and are not an error
                                    if io_err.kind() == ErrorKind::WouldBlock
                                        || io_err.kind() == ErrorKind::Interrupted
                                    {
                                        return Ok(()); // all is well, we try again later
                                    }
                                    return Err(io_err);
                                }
                            }
                        }
                    }
                }
                match channel
                    .stream
                    .write(&write_task.buffer[write_task.offset..])
                {
                    Ok(n) => {
                        write_task.offset += n;
                        if write_task.offset >= write_task.buffer.len() {
                            // task is done
                            channel.bytes_sent += write_task.buffer.len() as u64;
                            channel.rounds += 1;
                            write_task_queue.pop();
                        }
                        Ok(())
                    }
                    Err(io_err) => {
                        // a few error types are expected, and are not an error
                        if io_err.kind() == ErrorKind::WouldBlock
                            || io_err.kind() == ErrorKind::Interrupted
                        {
                            return Ok(()); // all is well, we try again later
                        }
                        Err(io_err)
                    }
                }
            }
            None => Ok(()), // no write task, nothing to do
        }
    }

    fn non_blocking_write_tls(channel: &mut NonBlockingCommChannel) -> io::Result<()> {
        match channel.stream.write_tls() {
            Ok(_) => Ok(()), // here we can ignore the reported number of written bytes since they have been counted before in [Self::non_blocking_write]
            Err(io_err) => {
                // a few error types are expected, and are not an error
                if io_err.kind() == ErrorKind::WouldBlock || io_err.kind() == ErrorKind::Interrupted
                {
                    return Ok(()); // all is well, we try again later
                }
                Err(io_err)
            }
        }
    }
}

#[derive(Debug)]
pub struct IoLayerOwned {
    task_layer: OnceCell<IoLayer>,
    sync_prev_channel: Receiver<()>,
    sync_next_channel: Receiver<()>,
    io_prev_thread_handle: JoinHandle<(IoThreadContext, io::Result<()>)>,
    io_next_thread_handle: JoinHandle<(IoThreadContext, io::Result<()>)>,
}

#[derive(Debug, Clone)]
pub struct IoLayer {
    task_prev_channel: Sender<Task>,
    task_next_channel: Sender<Task>,
}

#[cfg(feature = "verbose-timing")]
lazy_static! {
    pub static ref IO_TIMER: Mutex<Timer> = Mutex::new(Timer::new());
}

lazy_static! {
    static ref IO_COMM_STATS: Mutex<CombinedCommStats> = Mutex::new(CombinedCommStats::empty());
}

impl IoLayerOwned {
    pub fn spawn_io(comm_prev: CommChannel, comm_next: CommChannel) -> io::Result<Self> {
        // setup thread for I/O to prev party
        let (send_prev, rcv_prev) = channel();
        let (mut ctx_prev, sync_receiver_prev) = IoThreadContext::new(comm_prev, rcv_prev)?;

        // setup thread for I/O to next party
        let (send_next, rcv_next) = channel();
        let (mut ctx_next, sync_receiver_next) = IoThreadContext::new(comm_next, rcv_next)?;

        let handle_prev = thread::spawn(move || {
            // the IO loop
            let res = ctx_prev.handle_io(Direction::Previous);
            res.unwrap();
            // when exit or error
            (ctx_prev, Ok(()))
        });
        let handle_next = thread::spawn(move || {
            // the IO loop
            let res = ctx_next.handle_io(Direction::Next);
            res.unwrap();
            // when exit or error
            (ctx_next, Ok(()))
        });

        let task_layer = OnceCell::new();
        task_layer.set(IoLayer::new(send_prev, send_next)).unwrap(); // OnceCell is empty

        Ok(Self {
            task_layer,
            sync_prev_channel: sync_receiver_prev,
            sync_next_channel: sync_receiver_next,
            io_prev_thread_handle: handle_prev,
            io_next_thread_handle: handle_next,
        })
    }

    pub fn send(&self, direction: Direction, bytes: Vec<u8>) {
        self.task_layer.get().unwrap().send(direction, bytes)
    }

    pub fn send_field<'a, F: Field + 'a>(
        &self,
        direction: Direction,
        elements: impl IntoIterator<Item = impl Borrow<F>>,
        len: usize,
    ) {
        self.task_layer
            .get()
            .unwrap()
            .send_field(direction, elements, len)
    }

    pub fn receive(&self, direction: Direction, length: usize) -> receiver::VecReceiver {
        self.task_layer.get().unwrap().receive(direction, length)
    }

    pub fn receive_slice<'a>(
        &self,
        direction: Direction,
        dst: &'a mut [u8],
    ) -> receiver::SliceReceiver<'a> {
        self.task_layer.get().unwrap().receive_slice(direction, dst)
    }

    pub fn receive_field<F: Field>(
        &self,
        direction: Direction,
        num_elements: usize,
    ) -> receiver::FieldVectorReceiver<F> {
        self.task_layer
            .get()
            .unwrap()
            .receive_field(direction, num_elements)
    }

    pub fn receive_field_slice<'a, F: Field>(
        &self,
        direction: Direction,
        dst: &'a mut [F],
    ) -> receiver::FieldSliceReceiver<'a, F> {
        self.task_layer
            .get()
            .unwrap()
            .receive_field_slice(direction, dst)
    }

    pub fn wait_for_completion(&self) {
        #[cfg(feature = "verbose-timing")]
        let start = Instant::now();
        let task_layer = self.task_layer.get().unwrap();
        // first send a Sync task, then block and wait to the IO thread to sync
        match (
            task_layer.task_prev_channel.send(Task::Sync {
                write_comm_stats: false,
            }),
            task_layer.task_next_channel.send(Task::Sync {
                write_comm_stats: false,
            }),
        ) {
            (Ok(()), Ok(())) => {
                let sync_prev = self.sync_prev_channel.recv();
                let sync_next = self.sync_next_channel.recv();
                match (sync_prev, sync_next) {
                    (Ok(()), Ok(())) => {
                        // sync is completed, return the function to caller
                        #[cfg(feature = "verbose-timing")]
                        {
                            let end = start.elapsed();
                            IO_TIMER.lock().unwrap().report_time("io", end);
                        }
                    }
                    _ => panic!("The IO is already closed"),
                }
            }
            _ => panic!("The IO is already closed"),
        }
    }

    pub fn shutdown(mut self) -> io::Result<(NonBlockingCommChannel, NonBlockingCommChannel)> {
        let task_layer = self.task_layer.take().unwrap();
        // first send Sync task
        match task_layer.task_prev_channel.send(Task::Sync {
            write_comm_stats: false,
        }) {
            Ok(()) => (),
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::NotConnected,
                    "Task channel to prev no longer connected",
                ))
            }
        }
        match task_layer.task_next_channel.send(Task::Sync {
            write_comm_stats: false,
        }) {
            Ok(()) => (),
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::NotConnected,
                    "Task channel to next no longer connected",
                ))
            }
        }
        // then close task channel to indicate closing
        drop(task_layer.task_prev_channel);
        drop(task_layer.task_next_channel);
        // then wait for sync
        match self.sync_prev_channel.recv() {
            Ok(()) => (),
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::NotConnected,
                    "Sync channel to prev no longer connected",
                ))
            }
        }
        match self.sync_next_channel.recv() {
            Ok(()) => (),
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::NotConnected,
                    "Sync channel to next no longer connected",
                ))
            }
        }
        // finally wait for IO thread
        let res_prev = match self.io_prev_thread_handle.join() {
            Ok((ctx_prev, Ok(()))) => Ok(ctx_prev.comm),
            Ok((_, Err(io_err_prev))) => Err(io_err_prev),
            Err(_join_err) => Err(io::Error::new(
                ErrorKind::Other,
                "Error when joining the I/O thread of prev",
            )),
        };
        let res_next = match self.io_next_thread_handle.join() {
            Ok((ctx_next, Ok(()))) => Ok(ctx_next.comm),
            Ok((_, Err(io_err_next))) => Err(io_err_next),
            Err(_join_err) => Err(io::Error::new(
                ErrorKind::Other,
                "Error when joining the I/O thread of next",
            )),
        };
        match (res_prev, res_next) {
            (Ok(comm_prev), Ok(comm_next)) => Ok((comm_prev, comm_next)),
            (Err(err), _) => Err(err),
            (_, Err(err)) => Err(err),
        }
    }

    pub fn reset_comm_stats(&self) -> CombinedCommStats {
        let task_layer = self.task_layer.get().unwrap();
        match (
            task_layer.task_prev_channel.send(Task::Sync {
                write_comm_stats: true,
            }),
            task_layer.task_next_channel.send(Task::Sync {
                write_comm_stats: true,
            }),
        ) {
            (Ok(()), Ok(())) => {
                let sync_prev = self.sync_prev_channel.recv();
                let sync_next = self.sync_next_channel.recv();
                match (sync_prev, sync_next) {
                    (Ok(()), Ok(())) => {
                        // sync is completed, return the function to caller
                        let mut guard = IO_COMM_STATS.lock().unwrap();
                        let comm_stats = *guard;
                        guard.prev.reset();
                        guard.next.reset();
                        comm_stats
                    }
                    _ => panic!("The IO is already closed"),
                }
            }
            _ => panic!("The IO is already closed"),
        }
    }

    pub fn clone_io_layer(&self) -> OnceCell<IoLayer> {
        self.task_layer.clone()
    }
}

impl IoLayer {
    fn new(task_prev_channel: Sender<Task>, task_next_channel: Sender<Task>) -> Self {
        Self {
            task_prev_channel,
            task_next_channel,
        }
    }

    fn send_helper(&self, direction: Direction, thread_id: Option<usize>, bytes: Vec<u8>) {
        let thread_id = thread_id.map(|t| u64::try_from(t).expect("ThreadId too large"));
        if !bytes.is_empty() {
            let channel = match direction {
                Direction::Previous => &self.task_prev_channel,
                Direction::Next => &self.task_next_channel,
            };
            match channel.send(Task::Write {
                thread_id,
                data: bytes,
            }) {
                Ok(()) => (),
                Err(_) => panic!("The IO is already closed"),
            }
        }
    }

    pub fn send(&self, direction: Direction, bytes: Vec<u8>) {
        self.send_helper(direction, None, bytes)
    }

    pub fn send_thread(&self, direction: Direction, thread_id: usize, bytes: Vec<u8>) {
        self.send_helper(direction, Some(thread_id), bytes)
    }

    pub fn receive(&self, direction: Direction, length: usize) -> receiver::VecReceiver {
        receiver::VecReceiver::new(self.receive_raw(direction, None, length))
    }

    pub fn receive_thread(
        &self,
        direction: Direction,
        thread_id: usize,
        length: usize,
    ) -> receiver::VecReceiver {
        receiver::VecReceiver::new(self.receive_raw(direction, Some(thread_id), length))
    }

    fn receive_raw(
        &self,
        direction: Direction,
        thread_id: Option<usize>,
        length: usize,
    ) -> oneshot::Receiver<Vec<u8>> {
        let thread_id = thread_id.map(|t| u64::try_from(t).expect("ThreadId too large"));
        let (send, recv) = oneshot::channel();
        if length > 0 {
            let channel = match direction {
                Direction::Previous => &self.task_prev_channel,
                Direction::Next => &self.task_next_channel,
            };
            match channel.send(Task::Read {
                thread_id,
                length,
                mailback: send,
            }) {
                Ok(()) => recv,
                Err(_) => panic!("The IO is already closed"),
            }
        } else {
            // immediately populate recv
            send.send(Vec::new()).unwrap(); // this is safe since `send` returns Err only if recv has been dropped
            recv
        }
    }

    pub fn receive_slice<'a>(
        &self,
        direction: Direction,
        dst: &'a mut [u8],
    ) -> receiver::SliceReceiver<'a> {
        receiver::SliceReceiver::new(self.receive_raw(direction, None, dst.len()), dst)
    }

    pub fn receive_slice_thread<'a>(
        &self,
        direction: Direction,
        thread_id: usize,
        dst: &'a mut [u8],
    ) -> receiver::SliceReceiver<'a> {
        receiver::SliceReceiver::new(self.receive_raw(direction, Some(thread_id), dst.len()), dst)
    }

    pub fn send_field<'a, F: Field + 'a>(
        &self,
        direction: Direction,
        elements: impl IntoIterator<Item = impl Borrow<F>>,
        len: usize,
    ) {
        #[cfg(feature = "verbose-timing")]
        let start = Instant::now();
        let as_bytes = F::as_byte_vec(elements, len);
        #[cfg(feature = "verbose-timing")]
        {
            let end = start.elapsed();
            IO_TIMER.lock().unwrap().report_time("ser", end);
        }
        self.send(direction, as_bytes)
    }

    pub fn send_field_thread<'a, F: Field + 'a>(
        &self,
        direction: Direction,
        thread_id: usize,
        elements: impl IntoIterator<Item = impl Borrow<F>>,
        len: usize,
    ) {
        #[cfg(feature = "verbose-timing")]
        let start = Instant::now();
        let as_bytes = F::as_byte_vec(elements, len);
        #[cfg(feature = "verbose-timing")]
        {
            let end = start.elapsed();
            IO_TIMER.lock().unwrap().report_time("ser", end);
        }
        self.send_helper(direction, Some(thread_id), as_bytes)
    }

    pub fn receive_field<F: Field>(
        &self,
        direction: Direction,
        num_elements: usize,
    ) -> receiver::FieldVectorReceiver<F> {
        receiver::FieldVectorReceiver::new(
            self.receive_raw(direction, None, F::serialized_size(num_elements)),
            num_elements,
        )
    }

    pub fn receive_field_thread<F: Field>(
        &self,
        direction: Direction,
        thread_id: usize,
        num_elements: usize,
    ) -> receiver::FieldVectorReceiver<F> {
        receiver::FieldVectorReceiver::new(
            self.receive_raw(direction, Some(thread_id), F::serialized_size(num_elements)),
            num_elements,
        )
    }

    pub fn receive_field_slice<'a, F: Field>(
        &self,
        direction: Direction,
        dst: &'a mut [F],
    ) -> receiver::FieldSliceReceiver<'a, F> {
        receiver::FieldSliceReceiver::new(
            self.receive_raw(direction, None, F::serialized_size(dst.len())),
            dst,
        )
    }

    pub fn receive_field_slice_thread<'a, F: Field>(
        &self,
        direction: Direction,
        thread_id: usize,
        dst: &'a mut [F],
    ) -> receiver::FieldSliceReceiver<'a, F> {
        receiver::FieldSliceReceiver::new(
            self.receive_raw(direction, Some(thread_id), F::serialized_size(dst.len())),
            dst,
        )
    }
}

#[cfg(test)]
mod test {
    use std::{collections::BTreeMap, iter::repeat, thread};

    use itertools::Itertools;
    use rand::{seq::SliceRandom, thread_rng, CryptoRng, Rng, RngCore};

    use crate::{
        network::{receiver::VecReceiver, task::U64_BYTE_SIZE, CommChannel},
        party::test::localhost_connect,
    };

    use super::{Direction, IoLayerOwned, TaskQueue};

    fn setup_comm_channels() -> ((CommChannel, CommChannel), (CommChannel, CommChannel)) {
        let (p1, p2, p3) = localhost_connect(|p| p, |p| p, |p| p);
        let p1 = p1.join().unwrap();
        let p2 = p2.join().unwrap();
        let p3 = p3.join().unwrap();
        // we return p1's channels
        let comm_prev = p1.comm_prev;
        let comm_next = p1.comm_next;
        let comm_prev_receiver = p3.comm_next;
        let comm_next_receiver = p2.comm_prev;
        // close the connection between p2 and p3
        drop(p2.comm_next);
        drop(p3.comm_prev);
        (
            (comm_prev, comm_prev_receiver),
            (comm_next, comm_next_receiver),
        )
    }

    fn check_connected(channel1: &mut CommChannel, channel2: &mut CommChannel) {
        let stream1 = channel1.stream.as_mut().unwrap();
        let stream2 = channel2.stream.as_mut().unwrap();
        let mut res = [0u8];
        stream1.as_mut_write().write_all(&[0x1]).unwrap();
        stream2.as_mut_read().read_exact(&mut res).unwrap();
        assert_eq!(&res, &[0x1]);
        stream2.as_mut_write().write_all(&[0x2]).unwrap();
        stream1.as_mut_read().read_exact(&mut res).unwrap();
        assert_eq!(&res, &[0x2]);
    }

    #[test]
    fn proper_shutdown_when_empty() {
        let ((comm_prev, mut comm_prev_receiver), (comm_next, mut comm_next_receiver)) =
            setup_comm_channels();
        let io = IoLayerOwned::spawn_io(comm_prev, comm_next).unwrap();
        let (nb_prev, nb_next) = io.shutdown().unwrap();
        let mut comm_prev = nb_prev.into_channel().unwrap();
        let mut comm_next = nb_next.into_channel().unwrap();

        // check if comm_prev <-> comm_prev_receiver is connected
        check_connected(&mut comm_prev, &mut comm_prev_receiver);
        check_connected(&mut comm_next, &mut comm_next_receiver);
    }

    fn random_bytes<R: Rng + CryptoRng>(rng: &mut R, length: usize) -> Vec<u8> {
        let mut buf = vec![0u8; length];
        rng.fill_bytes(&mut buf);
        buf
    }

    #[test]
    fn can_read_write_one() {
        let ((comm_prev, mut comm_prev_receiver), (comm_next, comm_next_receiver)) =
            setup_comm_channels();
        let io = IoLayerOwned::spawn_io(comm_prev, comm_next).unwrap();

        let mut rng = thread_rng();
        const N: usize = 20_000; // a larger number of bytes, hoping that this will cause blocking read/write

        // setup a read from comm_prev
        let data_to_read = random_bytes(&mut rng, N);
        // rng.fill_bytes(&mut data_to_read);
        comm_prev_receiver.write(&data_to_read).unwrap();
        let data_to_write = random_bytes(&mut rng, N);
        // rng.fill_bytes(&mut data_to_write);

        io.send(Direction::Previous, data_to_write.clone());
        let rcv = io.receive(Direction::Previous, data_to_read.len());

        let actual_read = rcv.recv().unwrap();
        assert_eq!(&data_to_read, &actual_read);
        let mut actual_write = vec![0u8; N];

        // synchronize before reading the counterpart
        io.wait_for_completion();

        comm_prev_receiver.read(&mut actual_write).unwrap();
        assert_eq!(&data_to_write, &actual_write);

        // check that order of tasks doesn't matter
        comm_prev_receiver.write(&data_to_read).unwrap();
        let rcv = io.receive(Direction::Previous, data_to_read.len());
        io.send(Direction::Previous, data_to_write.clone());
        let actual_read = rcv.recv().unwrap();
        assert_eq!(&data_to_read, &actual_read);

        // synchronize before reading the counterpart
        io.wait_for_completion();
        comm_prev_receiver.read(&mut actual_write).unwrap();
        assert_eq!(data_to_write, actual_write);

        io.shutdown().unwrap();
        drop(comm_next_receiver);
    }

    #[test]
    fn can_read_write_multiple_blocks_prev() {
        let ((comm_prev, mut comm_prev_receiver), (comm_next, _comm_next_receiver)) =
            setup_comm_channels();
        let io = IoLayerOwned::spawn_io(comm_prev, comm_next).unwrap();

        let mut rng = thread_rng();
        const N: usize = 20_000; // a larger number of bytes, hoping that this will cause blocking read/write
        let write_blocks: Vec<_> = (0..10).map(|_| random_bytes(&mut rng, N)).collect();
        let read_blocks: Vec<_> = (0..10).map(|_| random_bytes(&mut rng, N)).collect();

        let read_blocks_copy = read_blocks.clone();
        let write_blocks_copy = write_blocks.clone();
        let other_thread = thread::spawn(move || {
            for buf in read_blocks_copy {
                comm_prev_receiver.write(&buf).unwrap();
            }
            // receive all write blocks, and check if they are correct
            for buf in write_blocks_copy {
                let mut actual = vec![0u8; buf.len()];
                comm_prev_receiver.read(&mut actual).unwrap();
                assert_eq!(buf, actual);
            }
            comm_prev_receiver
        });

        let write_order = {
            let mut order: Vec<_> = repeat(1)
                .take(write_blocks.len())
                .chain(repeat(0).take(write_blocks.len()))
                .collect();
            order.shuffle(&mut rng);
            order
        };
        let mut read_index = 0;
        let mut write_index = 0;
        let mut read_handles = Vec::new();
        for order in write_order {
            if order == 0 {
                io.send(Direction::Previous, write_blocks[write_index].clone());
                write_index += 1;
            } else if order == 1 {
                read_handles.push(io.receive(Direction::Previous, read_blocks[read_index].len()));
                read_index += 1;
            }
        }
        assert_eq!(read_index, read_blocks.len());
        assert_eq!(write_index, write_blocks.len());

        // sync
        io.wait_for_completion();
        let _comm_prev_receiver = other_thread.join().unwrap();

        let actual_reads: Vec<_> = read_handles
            .into_iter()
            .map(|h| h.recv().unwrap())
            .collect();
        assert_eq!(read_blocks, actual_reads);

        io.shutdown().unwrap();
    }

    #[test]
    fn can_read_write_multiple_blocks_both() {
        let ((comm_prev, mut comm_prev_receiver), (comm_next, mut comm_next_receiver)) =
            setup_comm_channels();
        let io = IoLayerOwned::spawn_io(comm_prev, comm_next).unwrap();

        let mut rng = thread_rng();
        const N: usize = 20_000; // a larger number of bytes, hoping that this will cause blocking read/write
        let write_blocks1: Vec<_> = (0..10).map(|_| random_bytes(&mut rng, N)).collect();
        let read_blocks1: Vec<_> = (0..10).map(|_| random_bytes(&mut rng, N)).collect();
        let write_blocks2: Vec<_> = (0..10).map(|_| random_bytes(&mut rng, N)).collect();
        let read_blocks2: Vec<_> = (0..10).map(|_| random_bytes(&mut rng, N)).collect();

        let read_blocks1_copy = read_blocks1.clone();
        let write_blocks1_copy = write_blocks1.clone();
        let prev_thread = thread::spawn(move || {
            for buf in read_blocks1_copy {
                comm_prev_receiver.write(&buf).unwrap();
            }
            // receive all write blocks, and check if they are correct
            for buf in write_blocks1_copy {
                let mut actual = vec![0u8; buf.len()];
                comm_prev_receiver.read(&mut actual).unwrap();
                assert_eq!(buf, actual);
            }
            comm_prev_receiver
        });
        let read_blocks2_copy = read_blocks2.clone();
        let write_blocks2_copy = write_blocks2.clone();
        let next_thread = thread::spawn(move || {
            for buf in read_blocks2_copy {
                comm_next_receiver.write(&buf).unwrap();
            }
            // receive all write blocks, and check if they are correct
            for buf in write_blocks2_copy {
                let mut actual = vec![0u8; buf.len()];
                comm_next_receiver.read(&mut actual).unwrap();
                assert_eq!(buf, actual);
            }
            comm_next_receiver
        });

        let write_order = {
            let mut order: Vec<_> = repeat(1)
                .take(read_blocks1.len())
                .chain(repeat(0).take(write_blocks1.len()))
                .chain(
                    repeat(2)
                        .take(write_blocks2.len())
                        .chain(repeat(3).take(read_blocks2.len())),
                )
                .collect();
            order.shuffle(&mut rng);
            order
        };
        let mut read1_index = 0;
        let mut write1_index = 0;
        let mut read2_index = 0;
        let mut write2_index = 0;
        let mut read_prev_handles = Vec::new();
        let mut read_next_handles = Vec::new();
        for order in write_order {
            if order == 0 {
                io.send(Direction::Previous, write_blocks1[write1_index].clone());
                write1_index += 1;
            } else if order == 1 {
                read_prev_handles
                    .push(io.receive(Direction::Previous, read_blocks1[read1_index].len()));
                read1_index += 1;
            } else if order == 2 {
                io.send(Direction::Next, write_blocks2[write2_index].clone());
                write2_index += 1;
            } else if order == 3 {
                read_next_handles
                    .push(io.receive(Direction::Next, read_blocks2[read2_index].len()));
                read2_index += 1;
            }
        }
        assert_eq!(read1_index, read_blocks1.len());
        assert_eq!(write1_index, write_blocks1.len());
        assert_eq!(read2_index, read_blocks2.len());
        assert_eq!(write2_index, write_blocks2.len());

        // sync
        io.wait_for_completion();
        let _comm_prev_receiver = prev_thread.join().unwrap();
        let _comm_next_receiver = next_thread.join().unwrap();

        let actual_prev_reads: Vec<_> = read_prev_handles
            .into_iter()
            .map(|h| h.recv().unwrap())
            .collect();
        let actual_next_reads: Vec<_> = read_next_handles
            .into_iter()
            .map(|h| h.recv().unwrap())
            .collect();
        assert_eq!(read_blocks1, actual_prev_reads);
        assert_eq!(read_blocks2, actual_next_reads);

        io.shutdown().unwrap();
    }

    #[test]
    fn io_layer() {
        let (p1, p2, p3) = localhost_connect(|p| p, |p| p, |p| p);
        let p1 = p1.join().unwrap();
        let p2 = p2.join().unwrap();
        let p3 = p3.join().unwrap();

        let io1 = IoLayerOwned::spawn_io(p1.comm_prev, p1.comm_next).unwrap();
        let io2 = IoLayerOwned::spawn_io(p2.comm_prev, p2.comm_next).unwrap();
        let io3 = IoLayerOwned::spawn_io(p3.comm_prev, p3.comm_next).unwrap();

        fn send(
            io: &IoLayerOwned,
            msg_to_prev: String,
            msg_to_next: String,
        ) -> (VecReceiver, VecReceiver) {
            assert_eq!(msg_to_prev.len(), msg_to_next.len());
            let rcv_prev = io.receive(Direction::Previous, msg_to_prev.len());
            io.send(Direction::Next, msg_to_next.as_bytes().to_vec());
            io.send(Direction::Previous, msg_to_prev.as_bytes().to_vec());
            let rcv_next = io.receive(Direction::Next, msg_to_next.len());
            (rcv_prev, rcv_next)
        }

        fn blow_up(msg: &str) -> String {
            // extend the length of msg
            const N: usize = 1000;
            repeat(()).take(N).map(|_| msg).join("")
        }

        let (p3p1, p2p1) = send(&io1, blow_up("P1-P3"), blow_up("P1-P2"));
        let (p1p2, p3p2) = send(&io2, blow_up("P2-P1"), blow_up("P2-P3"));
        let (p2p3, p1p3) = send(&io3, blow_up("P3-P2"), blow_up("P3-P1"));

        assert_eq!(blow_up("P3-P1").as_bytes(), p3p1.recv().unwrap());
        assert_eq!(blow_up("P2-P1").as_bytes(), p2p1.recv().unwrap());
        assert_eq!(blow_up("P1-P2").as_bytes(), p1p2.recv().unwrap());
        assert_eq!(blow_up("P3-P2").as_bytes(), p3p2.recv().unwrap());
        assert_eq!(blow_up("P2-P3").as_bytes(), p2p3.recv().unwrap());
        assert_eq!(blow_up("P1-P3").as_bytes(), p1p3.recv().unwrap());

        let (_comm1, _comm2) = io1.shutdown().unwrap();
        let (_comm3, _comm4) = io2.shutdown().unwrap();
        let (_comm5, _comm6) = io3.shutdown().unwrap();
    }

    #[test]
    fn sending_receiving_empty() {
        let ((comm_prev, comm_prev_receiver), (comm_next, comm_next_receiver)) =
            setup_comm_channels();
        let io = IoLayerOwned::spawn_io(comm_prev, comm_next).unwrap();
        // send and receive empty messages
        let empty = Vec::new();
        io.send(Direction::Next, empty.clone());
        io.send(Direction::Previous, empty);
        let rcv_next = io.receive(Direction::Next, 0);
        let rcv_prev = io.receive(Direction::Previous, 0);

        assert!(rcv_next.recv().unwrap().is_empty());
        assert!(rcv_prev.recv().unwrap().is_empty());
        io.wait_for_completion();
        io.shutdown().unwrap();
        drop(comm_prev_receiver);
        drop(comm_next_receiver)
    }

    #[test]
    fn task_queue() {
        let mut q = TaskQueue::new();
        assert!(q.is_empty());
        assert_eq!(q.peek(), None);
        assert_eq!(q.peek_or_peek_from_any_thread_id(), None);
        // can insert and pop elements in expected order
        q.put(None, 1);
        assert!(!q.is_empty());
        q.put(None, 2);
        assert_eq!(Some(&mut 1), q.peek());
        assert_eq!(Some(&mut 1), q.peek_or_peek_from_any_thread_id());
        assert_eq!(Some(1), q.pop());
        assert_eq!(Some(2), q.pop());
        assert!(q.is_empty());

        // can insert elements with thread_id
        q.put(Some(10), 15);
        assert!(!q.is_empty());
        q.put(Some(20), 27);
        q.put(Some(10), 17);

        assert_eq!(None, q.peek()); // no non-thread_id element in queue
        let el = q.peek_or_peek_from_any_thread_id();
        assert!(el.is_some());
        // el now moved to the normal queue
        let mut el = el.unwrap().clone();
        assert_eq!(Some(&mut el), q.peek());
        assert_eq!(Some(&mut el), q.peek_or_peek_from_any_thread_id());

        // pop el off
        assert_eq!(Some(el), q.pop());
        assert_eq!(None, q.peek()); // no non-thread_id element in queue
        let el = q.peek_or_peek_from_any_thread_id();
        assert!(el.is_some());

        // el now moved to the normal queue
        let mut el = el.unwrap().clone();
        assert_eq!(Some(&mut el), q.peek());
        assert_eq!(Some(&mut el), q.peek_or_peek_from_any_thread_id());

        // pop el off
        assert_eq!(Some(el), q.pop());
        assert_eq!(None, q.peek()); // no non-thread_id element in queue

        // remove last element
        q.peek_or_peek_from_any_thread_id();
        assert!(q.pop().is_some());
        assert!(q.is_empty());

        // can also directly remove from thread_id
        q.put(Some(10), 15);
        assert!(!q.is_empty());
        q.put(Some(20), 27);
        q.put(Some(10), 17);
        assert_eq!(Some(15), q.pop_with_thread_id(10));
        assert_eq!(Some(27), q.pop_with_thread_id(20));
        assert_eq!(Some(17), q.pop_with_thread_id(10));
        assert!(q.is_empty());
    }

    #[test]
    fn send_receive_threaded_one() {
        let ((comm_prev, mut comm_prev_receiver), (comm_next, _comm_next_receiver)) =
            setup_comm_channels();
        let io_owned = IoLayerOwned::spawn_io(comm_prev, comm_next).unwrap();
        let io = io_owned.task_layer.get().unwrap();

        let mut rng = thread_rng();
        const N: usize = 20_000; // a larger number of bytes, hoping that this will cause blocking read/write
        const N_THREADS: usize = 10;

        let mut data_send = (0..N_THREADS)
            .map(|id| {
                let mut bytes = vec![0u8; N];
                rng.fill_bytes(&mut bytes);
                (id, bytes)
            })
            .collect_vec();

        data_send.shuffle(&mut rng);

        let mut data_receive = (0..N_THREADS)
            .map(|id| {
                let mut bytes = vec![0u8; N];
                rng.fill_bytes(&mut bytes);
                (id * N, bytes)
            })
            .collect_vec();
        let data_receive_clone = data_receive.clone();

        data_receive.shuffle(&mut rng);

        // setup as many receivers
        let mut rcv_order = (0..N_THREADS).collect_vec();
        rcv_order.shuffle(&mut rng);
        let recv = rcv_order
            .into_iter()
            .map(|id| (id * N, io.receive_thread(Direction::Previous, id * N, N)))
            .collect_vec();

        for (id, data) in &data_send {
            io.send_thread(Direction::Previous, id * N, data.clone());
        }

        let mut received = BTreeMap::new();
        // first receive a bit
        for _ in 0..(N_THREADS / 2) {
            let mut buf = vec![0u8; N + U64_BYTE_SIZE];
            comm_prev_receiver.read(&mut buf).unwrap();
            let mut id = [0u8; U64_BYTE_SIZE];
            id.copy_from_slice(&buf[..U64_BYTE_SIZE]);
            received.insert(u64::from_le_bytes(id), buf);
        }
        // then send a bit
        for _ in 0..(N_THREADS / 2) {
            let (id, data) = data_receive.pop().unwrap();
            comm_prev_receiver
                .write(&(id as u64).to_le_bytes())
                .unwrap();
            comm_prev_receiver.write(&data).unwrap();
        }
        // receive the rest
        for _ in (N_THREADS / 2)..N_THREADS {
            let mut buf = vec![0u8; N + U64_BYTE_SIZE];
            comm_prev_receiver.read(&mut buf).unwrap();
            let mut id = [0u8; U64_BYTE_SIZE];
            id.copy_from_slice(&buf[..U64_BYTE_SIZE]);
            received.insert(u64::from_le_bytes(id), buf);
        }
        // send the rest
        for _ in (N_THREADS / 2)..N_THREADS {
            let (id, data) = data_receive.pop().unwrap();
            comm_prev_receiver
                .write(&(id as u64).to_le_bytes())
                .unwrap();
            comm_prev_receiver.write(&data).unwrap();
        }
        assert!(data_receive.is_empty()); // should be all

        // wait on receivers
        let recv = recv
            .into_iter()
            .map(|(id, r)| (id, r.recv().unwrap()))
            .collect_vec();
        // sync
        io_owned.wait_for_completion();

        // check that data was correctly received
        for (id, expected) in data_receive_clone {
            let mut found = false;
            for (r_id, actual) in &recv {
                if *r_id == id {
                    assert_eq!(&expected, actual);
                    found = true;
                }
            }
            assert!(found);
        }

        // check that data was correctly sent
        for (id, expected) in data_send {
            let actual = received
                .remove(&((N * id) as u64))
                .expect("id not received");
            assert_eq!(expected, actual[U64_BYTE_SIZE..]);
        }
        assert!(received.is_empty());

        io_owned.shutdown().unwrap();
    }
}
