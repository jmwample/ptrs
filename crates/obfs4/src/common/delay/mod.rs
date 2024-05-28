use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{sink::Sink, Future};
use tokio::time::{Instant, Sleep};

use pin_project::pin_project;

type DurationFn = fn() -> Duration;

#[pin_project]
pub struct DelayedSink<Si, Item> {
    // #[pin]
    // sink: Si,
    // #[pin]
    // sleep: Sleep,
    sink: Pin<Box<Si>>,
    sleep: Pin<Box<Sleep>>,
    delay_fn: DurationFn,
    _item: PhantomData<Item>,
}

impl<Item, Si: Sink<Item>> DelayedSink<Si, Item> {
    pub fn new(sink: Si, delay_fn: DurationFn) -> Self {
        let delay = delay_fn();
        let sleep = tokio::time::sleep(delay);
        Self {
            // sink,
            // sleep,
            sink: Box::pin(sink),
            sleep: Box::pin(sleep),
            delay_fn,
            _item: PhantomData {},
        }
    }
}

impl<Item, Si: Sink<Item>> Sink<Item> for DelayedSink<Si, Item> {
    type Error = Si::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let s = self.project();
        match (s.sink.as_mut().poll_ready(cx), s.sleep.as_mut().poll(cx)) {
            (Poll::Ready(k), Poll::Ready(_)) => Poll::Ready(k),
            _ => Poll::Pending,
        }
    }

    fn start_send(self: Pin<&mut Self>, item: Item) -> Result<(), Self::Error> {
        let s = self.project();
        if let Err(e) = s.sink.as_mut().start_send(item) {
            return Err(e);
        }

        let delay = (*s.delay_fn)();

        if delay.is_zero() {
            s.sleep
                .as_mut()
                .reset(Instant::now() + delay);
        }
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.as_mut().poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project().sink.as_mut().poll_close(cx)
    }
}

#[cfg(test)]
mod testing {
    use super::*;
    use futures::sink::{self, SinkExt};
    use std::time::Instant;
    use rand_distr::{Normal, Distribution};

    #[tokio::test]
    async fn delay_sink() {
        let start = Instant::now();

        let unfold = sink::unfold(0, |mut sum, i: i32| async move {
            sum += i;
            eprintln!("{} - {:?}", i, Instant::now().duration_since(start));
            Ok::<_, futures::never::Never>(sum)
        });
        futures::pin_mut!(unfold);

        // let mut delayed_unfold = DelayedSink::new(unfold, || Duration::from_secs(1));
        let mut delayed_unfold = DelayedSink::new(unfold, delay_distribution);
        delayed_unfold.send(5).await.unwrap();
        delayed_unfold.send(4).await.unwrap();
        delayed_unfold.send(3).await.unwrap();
    }

    fn delay_distribution() -> Duration {
        let distr = Normal::new(500.0, 100.0).unwrap();
        let dur_ms = distr.sample(&mut rand::thread_rng());
        Duration::from_millis(dur_ms as u64)
    }
}
