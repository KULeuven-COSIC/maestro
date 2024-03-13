use std::{borrow::Borrow, collections::VecDeque, io::{self, ErrorKind, Read, Write}, sync::mpsc::{channel, sync_channel, Receiver, RecvError, Sender, SyncSender, TryRecvError}, thread::{self, JoinHandle}};

use crate::share::Field;

use super::{non_blocking::NonBlockingCommChannel, receiver, CommChannel};

#[derive(Copy, Clone, Debug)]
pub enum Direction { Next, Previous }

pub enum Task {
    Write { direction: Direction, data: Vec<u8>},
    Read { direction: Direction, length: usize, mailback: oneshot::Sender<Vec<u8>> },
    Sync
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
            mailback
        }
    }
}

struct WriteTask {
    buffer: Vec<u8>,
    offset: usize
}

impl WriteTask {
    pub fn new(buffer: Vec<u8>) -> Self {
        Self {
            buffer,
            offset: 0,
        }
    }
}

struct TaskQueue<T> {
    queue_next: VecDeque<T>,
    queue_prev: VecDeque<T>,
}

impl<T> TaskQueue<T> {
    pub fn new() -> Self {
        Self {
            queue_next: VecDeque::new(),
            queue_prev: VecDeque::new(),
        }
    }

    pub fn put(&mut self, direction: Direction, t: T) {
        match direction {
            Direction::Next => self.queue_next.push_back(t),
            Direction::Previous => self.queue_prev.push_back(t),
        }
    }

    pub fn pop(&mut self, direction: Direction) -> Option<T> {
        match direction {
            Direction::Next => self.queue_next.pop_front(),
            Direction::Previous => self.queue_prev.pop_front(),
        }
    }

    pub fn peek(&mut self, direction: Direction) -> Option<&mut T> {
        match direction {
            Direction::Next => self.queue_next.front_mut(),
            Direction::Previous => self.queue_prev.front_mut(),
        }
    }

    pub fn is_empty(&self,) -> bool {
        self.queue_next.is_empty() && self.queue_prev.is_empty()
    }

    pub fn is_empty_for(&self, direction: Direction) -> bool {
        match direction {
            Direction::Next => self.queue_next.is_empty(),
            Direction::Previous => self.queue_prev.is_empty(),
        }
    }
}

enum State {
    WaitingForTasks,
    Working { sync_requested: bool, close_requested: bool },
    Sync { close_requested: bool },
    Close
}

impl State {
    pub fn is_working(&self) -> bool {
        match self {
            Self::Working { .. } => true,
            _ => false
        }
    }
}

struct IoThreadContext {
    comm_next: NonBlockingCommChannel,
    comm_prev: NonBlockingCommChannel,
    read_tasks_receiver: Receiver<Task>,
    read_queue: TaskQueue<ReadTask>,
    write_queue: TaskQueue<WriteTask>,
    sync: SyncSender<()>,
    state: State,
}

impl IoThreadContext {

    pub fn new(comm_next: CommChannel, comm_prev: CommChannel, task_channel: Receiver<Task>) -> io::Result<(Self, Receiver<()>)> {
        let (send, receive) = sync_channel(0); // bound 0 creates rendez-vouz channel
        Ok((Self {
            comm_next: NonBlockingCommChannel::from_channel(comm_next)?,
            comm_prev: NonBlockingCommChannel::from_channel(comm_prev)?,
            read_tasks_receiver: task_channel,
            read_queue: TaskQueue::new(),
            write_queue: TaskQueue::new(),
            sync: send,
            state: State::WaitingForTasks,
        }, receive))
    }

    fn handle_io(&mut self) -> io::Result<()> {
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
                                    Self::non_blocking_write(&mut self.comm_prev, &mut self.write_queue, Direction::Previous)?;
                                    Self::non_blocking_write(&mut self.comm_next, &mut self.write_queue, Direction::Next)?;
                                }
                                // try to read
                                if !self.read_queue.is_empty() {
                                    Self::non_blocking_read(&mut self.comm_prev, &mut self.read_queue, Direction::Previous)?;
                                    Self::non_blocking_read(&mut self.comm_next, &mut self.read_queue, Direction::Next)?;
                                }
                                if self.write_queue.is_empty() && self.read_queue.is_empty() {
                                    self.state = State::WaitingForTasks; // the added task was small enough to be completed right away
                                }
                            }
                        },
                        Err(RecvError) => {
                            // the sender disconnected, this indicates closing
                            self.state = State::Close;
                        }
                    }
                },
                State::Working { sync_requested, close_requested } => {
                    if self.read_queue.is_empty() && self.write_queue.is_empty() {
                        self.state = if sync_requested {
                            State::Sync { close_requested }
                        }else if close_requested {
                            State::Close
                        }else{
                            // nothing to do, wait for new tasks
                            State::WaitingForTasks
                        };
                    }else{
                        // there is work to do
                        if !self.write_queue.is_empty_for(Direction::Previous) {
                            Self::non_blocking_write(&mut self.comm_prev, &mut self.write_queue, Direction::Previous)?;
                        }
                        if !self.write_queue.is_empty_for(Direction::Next) {
                            Self::non_blocking_write(&mut self.comm_next, &mut self.write_queue, Direction::Next)?;
                        }
                        if !self.read_queue.is_empty_for(Direction::Previous) {
                            Self::non_blocking_read(&mut self.comm_prev, &mut self.read_queue, Direction::Previous)?;
                        }
                        if !self.read_queue.is_empty_for(Direction::Next) {
                            Self::non_blocking_read(&mut self.comm_next, &mut self.read_queue, Direction::Next)?;
                        }

                        // let's see if new tasks are available
                        self.add_new_tasks_non_blocking();
                    }
                },
                State::Sync { close_requested } => {
                    // the protocol wants to sync and all tasks are done
                    match self.sync.send(()) {
                        Ok(()) => {
                            self.state = if close_requested {
                                State::Close // sync took place, close
                            }else{
                                State::WaitingForTasks // sync took place, wait for new tasks
                            };
                        },
                        Err(_) => panic!("The receiver for the sync channel was dropped.")
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
            Task::Read { direction, length, mailback } => {
                self.read_queue.put(direction, ReadTask::new(length, mailback));
                if !self.state.is_working() {
                    self.state = State::Working { sync_requested: false,  close_requested: false }
                }
            },
                
            Task::Write { direction, data } => {
                self.write_queue.put(direction, WriteTask::new(data));
                if !self.state.is_working() {
                    self.state = State::Working { sync_requested: false,  close_requested: false }
                }
            },

            Task::Sync => { 
                if let State::Working { close_requested,  .. } = self.state {
                    // there are tasks left that will be completed before sync
                    self.state = State::Working { sync_requested: true, close_requested };
                }else{
                    self.state = State::Sync { close_requested: false };
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
                },
                Err(TryRecvError::Empty) => cont = false,
                Err(TryRecvError::Disconnected) => {
                    // the sender disconnected, this indicates closing
                    cont = false;
                    if let State::Working { sync_requested, .. } = self.state {
                        self.state = State::Working { sync_requested, close_requested: true }
                    }
                    
                }
            }
        }
        
    }

    fn non_blocking_read(channel: &mut NonBlockingCommChannel, read_task_queue: &mut TaskQueue<ReadTask>, direction: Direction) -> io::Result<()> {
        match read_task_queue.peek(direction) {
            Some(read_task) => {
                let buf = &mut read_task.buffer[read_task.offset..];
                match channel.stream.read(buf) {
                    Ok(n) => {
                        read_task.offset += n;
                        if read_task.offset >= read_task.length {
                            // task is done
                            let t = read_task_queue.pop(direction).unwrap(); // this should not panic since we peeked before
                            channel.bytes_received += t.length as u64;
                            channel.rounds += 1;
                            // send the result back
                            t.mailback.send(t.buffer).expect("Cannot send read result back; receiver was dropped.");
                        }
                        Ok(())
                    },
                    Err(io_err) => {
                        // a few error types are expected, and are not an error
                        if io_err.kind() == ErrorKind::WouldBlock || io_err.kind() == ErrorKind::Interrupted {
                            return Ok(()); // all is well, we try again later
                        }
                        Err(io_err)
                    }
                }
                
            },
            None => Ok(()), // no read task, nothing to do
        }


        
    }

    fn non_blocking_write(channel: &mut NonBlockingCommChannel, write_task_queue: &mut TaskQueue<WriteTask>, direction: Direction) -> io::Result<()> {
        match write_task_queue.peek(direction) {
            Some(write_task) => {
                match channel.stream.write(&write_task.buffer[write_task.offset..]) {
                    Ok(n) => {
                        write_task.offset += n;
                        if write_task.offset >= write_task.buffer.len() {
                            // task is done
                            channel.bytes_sent += write_task.buffer.len() as u64;
                            channel.rounds += 1;
                            write_task_queue.pop(direction);
                        }
                        Ok(())
                    },
                    Err(io_err) => {
                        // a few error types are expected, and are not an error
                        if io_err.kind() == ErrorKind::WouldBlock || io_err.kind() == ErrorKind::Interrupted {
                            return Ok(()); // all is well, we try again later
                        }
                        Err(io_err)
                    }
                }
                
            },
            None => Ok(()), // no write task, nothing to do
        }
    }
}

pub struct IoLayer {
    task_channel: Sender<Task>,
    sync_channel: Receiver<()>,
    io_thread_handle: JoinHandle<(IoThreadContext, io::Result<()>)>,
}

impl IoLayer {
    pub fn spawn_io(comm_prev: CommChannel, comm_next: CommChannel) -> io::Result<Self> {
        let (send, rcv) = channel();
        let (mut ctx, sync_receiver) = IoThreadContext::new(comm_next, comm_prev, rcv)?;
        let handle = thread::spawn(move || {
            // the IO loop
            let res = ctx.handle_io();
            res.unwrap();
            // when exit or error
            (ctx, Ok(()))
        });
        Ok(Self {
            task_channel: send,
            sync_channel: sync_receiver,
            io_thread_handle: handle,
        })
    }

    pub fn send(&self, direction: Direction, bytes: Vec<u8>) {
        if !bytes.is_empty() {
            match self.task_channel.send(Task::Write { direction, data: bytes }) {
                Ok(()) => (),
                Err(_) => panic!("The IO is already closed"),
            }
        }
    }

    pub fn receive(&self, direction: Direction, length: usize) -> oneshot::Receiver<Vec<u8>> {
        let (send, recv) = oneshot::channel();
        if length > 0 {
            match self.task_channel.send(Task::Read { direction, length, mailback: send }) {
                Ok(()) => recv,
                Err(_) => panic!("The IO is already closed"),
            }
        }else{
            // immediately populate recv
            send.send(Vec::new()).unwrap(); // this is safe since `send` returns Err only if recv has been dropped
            recv
        }
    }

    pub fn receive_slice<'a>(&self, direction: Direction, dst: &'a mut [u8]) -> receiver::SliceReceiver<'a> {
        receiver::SliceReceiver::new(self.receive(direction, dst.len()), dst)
    }

    pub fn send_field<'a, F: Field + 'a>(&self, direction: Direction, elements: impl IntoIterator<Item=impl Borrow<F>>)
    {
        let as_bytes = F::as_byte_vec(elements);
        self.send(direction, as_bytes)
    }

    pub fn receive_field<F: Field>(&self, direction: Direction, num_elements: usize) -> receiver::FieldVectorReceiver<F> {
        receiver::FieldVectorReceiver::new(self.receive(direction, F::size()*num_elements))
    }

    pub fn receive_field_slice<'a, F: Field>(&self, direction: Direction, dst: &'a mut [F]) -> receiver::FieldSliceReceiver<'a, F> {
        receiver::FieldSliceReceiver::new(self.receive(direction, F::size()*dst.len()), dst)
    }

    pub fn wait_for_completion(&self) {
        // first send a Sync task, then block and wait to the IO thread to sync
        match self.task_channel.send(Task::Sync) {
            Ok(()) => {
                match self.sync_channel.recv() {
                    Ok(()) => (), // sync is completed, return the function to caller
                    Err(_) => panic!("The IO is already closed"),
                }
            },
            Err(_) => panic!("The IO is already closed"),
        }
    }

    pub fn shutdown(self) -> io::Result<(NonBlockingCommChannel, NonBlockingCommChannel)>{
        // first send Sync task
        match self.task_channel.send(Task::Sync) {
            Ok(()) => (),
            Err(_) => return Err(io::Error::new(ErrorKind::NotConnected, "Task channel no longer connected")),
        }
        // then close task channel to indicate closing
        drop(self.task_channel);
        // then wait for sync
        match self.sync_channel.recv() {
            Ok(()) => (),
            Err(_) => return Err(io::Error::new(ErrorKind::NotConnected, "Sync channel no longer connected")),
        }
        // finally wait for IO thread
        match self.io_thread_handle.join() {
            Ok((ctx, Ok(()))) => Ok((ctx.comm_prev, ctx.comm_next)),
            Ok((_, Err(io_err))) => Err(io_err),
            Err(_join_err) => Err(io::Error::new(ErrorKind::Other, "Error when joining the thread")),
        }
    }
}

#[cfg(test)]
mod test {
    use std::{iter::repeat, thread};

    use itertools::Itertools;
    use oneshot::Receiver;
    use rand::{seq::SliceRandom, thread_rng, CryptoRng, Rng};

    use crate::{network::CommChannel, party::test::localhost_connect};

    use super::{Direction, IoLayer};

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
        ((comm_prev, comm_prev_receiver), (comm_next, comm_next_receiver))
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
        let ((comm_prev, mut comm_prev_receiver), (comm_next, mut comm_next_receiver)) = setup_comm_channels();
        let io = IoLayer::spawn_io(comm_prev, comm_next).unwrap();
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
        let ((comm_prev, mut comm_prev_receiver), (comm_next, comm_next_receiver)) = setup_comm_channels();
        let io = IoLayer::spawn_io(comm_prev, comm_next).unwrap();

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
        let ((comm_prev, mut comm_prev_receiver), (comm_next, _comm_next_receiver)) = setup_comm_channels();
        let io = IoLayer::spawn_io(comm_prev, comm_next).unwrap();

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
            let mut order: Vec<_> = repeat(1).take(write_blocks.len()).chain(repeat(0).take(write_blocks.len())).collect();
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
            }else if order == 1 {
                read_handles.push(io.receive(Direction::Previous, read_blocks[read_index].len()));
                read_index += 1;
            }
        }
        assert_eq!(read_index, read_blocks.len());
        assert_eq!(write_index, write_blocks.len());

        // sync 
        io.wait_for_completion();
        let _comm_prev_receiver = other_thread.join().unwrap();

        let actual_reads: Vec<_> = read_handles.into_iter().map(|h| h.recv().unwrap()).collect();
        assert_eq!(read_blocks, actual_reads);

        io.shutdown().unwrap();
    }

    #[test]
    fn can_read_write_multiple_blocks_both() {
        let ((comm_prev, mut comm_prev_receiver), (comm_next, mut comm_next_receiver)) = setup_comm_channels();
        let io = IoLayer::spawn_io(comm_prev, comm_next).unwrap();

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
            let mut order: Vec<_> = repeat(1).take(read_blocks1.len()).chain(repeat(0).take(write_blocks1.len())).chain(repeat(2).take(write_blocks2.len()).chain(repeat(3).take(read_blocks2.len()))).collect();
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
            }else if order == 1 {
                read_prev_handles.push(io.receive(Direction::Previous, read_blocks1[read1_index].len()));
                read1_index += 1;
            }else if order == 2 {
                io.send(Direction::Next, write_blocks2[write2_index].clone());
                write2_index += 1;
            }else if order == 3 {
                read_next_handles.push(io.receive(Direction::Next, read_blocks2[read2_index].len()));
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

        let actual_prev_reads: Vec<_> = read_prev_handles.into_iter().map(|h| h.recv().unwrap()).collect();
        let actual_next_reads: Vec<_> = read_next_handles.into_iter().map(|h| h.recv().unwrap()).collect();
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

        let io1 = IoLayer::spawn_io(p1.comm_prev, p1.comm_next).unwrap();
        let io2 = IoLayer::spawn_io(p2.comm_prev, p2.comm_next).unwrap();
        let io3 = IoLayer::spawn_io(p3.comm_prev, p3.comm_next).unwrap();

        fn send(io: &IoLayer, msg_to_prev: String, msg_to_next: String) -> (Receiver<Vec<u8>>, Receiver<Vec<u8>>) {
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
        let ((comm_prev, comm_prev_receiver), (comm_next, comm_next_receiver)) = setup_comm_channels();
        let io = IoLayer::spawn_io(comm_prev, comm_next).unwrap();
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
}