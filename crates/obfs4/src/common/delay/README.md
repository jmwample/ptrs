# Sink Delays

Adding Structured Delays to rust sinks on event.


Example test using a sampled normal distribution for the delay after each
send (`start_send()` if not using `SinkExt`).

```rs
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
```

--- 

But I wanna go fast! Why would I ever want this???

-> This lets us control the delays (or leave them out) in between sink events.
As an example, we can control the delay between network writes, which helps when
reshaping the traffic fingerprint of a proxy connection.
