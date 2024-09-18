//! Weighted probability distribution
//!
//! The probdist module implements a weighted probability distribution suitable for
//! protocol parameterization.  To allow for easy reproduction of a given
//! distribution, the drbg package is used as the random number source.

use crate::common::drbg;

use std::cmp::{max, min};
use std::fmt;
use std::sync::{Arc, Mutex};

use rand::{seq::SliceRandom, Rng};

const MIN_VALUES: i32 = 1;
const MAX_VALUES: i32 = 100;

/// A weighted distribution of integer values.
#[derive(Clone)]
pub struct WeightedDist(Arc<Mutex<InnerWeightedDist>>);

struct InnerWeightedDist {
    min_value: i32,
    max_value: i32,
    biased: bool,

    values: Vec<i32>,
    weights: Vec<f64>,

    alias: Vec<usize>,
    prob: Vec<f64>,
}

impl WeightedDist {
    /// New creates a weighted distribution of values ranging from min to max
    /// based on a HashDrbg initialized with seed.  Optionally, bias the weight
    /// generation to match the ScrambleSuit non-uniform distribution from
    /// obfsproxy.
    pub fn new(seed: drbg::Seed, min: i32, max: i32, biased: bool) -> Self {
        let w = WeightedDist(Arc::new(Mutex::new(InnerWeightedDist {
            min_value: min,
            max_value: max,
            biased,
            values: vec![],
            weights: vec![],
            alias: vec![],
            prob: vec![],
        })));
        let _ = &w.reseed(seed);

        w
    }

    /// Generates a random value according to the generated distribution.
    pub fn sample(&self) -> i32 {
        let dist = self.0.lock().unwrap();

        let mut buf = [0_u8; 8];
        // Generate a fair die roll fro a $n$-sided die; call the side $i$.
        getrandom::getrandom(&mut buf).unwrap();

        #[cfg(target_pointer_width = "64")]
        let i = usize::from_ne_bytes(buf) % dist.values.len();

        #[cfg(target_pointer_width = "32")]
        let i = usize::from_ne_bytes(buf[0..4].try_into().unwrap()) % dist.values.len();

        // flip a coin that comes up heads with probability $prob[i]$.
        getrandom::getrandom(&mut buf).unwrap();
        let f = f64::from_ne_bytes(buf);
        if f < dist.prob[i] {
            // if the coin comes up "heads", use $i$
            dist.min_value + dist.values[i]
        } else {
            // otherwise use $alias[i]$.
            dist.min_value + dist.values[dist.alias[i]]
        }
    }

    /// Generates a new distribution with the same min/max based on a new seed.
    pub fn reseed(&self, seed: drbg::Seed) {
        let mut drbg = drbg::Drbg::new(Some(seed)).unwrap();

        let mut dist = self.0.lock().unwrap();
        dist.gen_values(&mut drbg);
        if dist.biased {
            dist.gen_biased_weights(&mut drbg);
        } else {
            dist.gen_uniform_weights(&mut drbg);
        }
        dist.gen_tables();
    }
}

impl InnerWeightedDist {
    // Creates a slice containing a random number of random values that, when
    // scaled by adding self.min_value, will fall into [min, max].
    fn gen_values<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        let mut n_values = self.max_value - self.min_value;

        let mut values: Vec<i32> = (0..=n_values).collect();
        values.shuffle(rng);
        n_values = max(n_values, MIN_VALUES);
        n_values = min(n_values, MAX_VALUES);

        let n_values = rng.gen_range(1..=n_values) as usize;
        self.values = values[..n_values].to_vec();
    }

    // generates a non-uniform weight list, similar to the scramblesuit
    // prob_dist mode.
    fn gen_biased_weights<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        self.weights = vec![0_f64; self.values.len()];

        let mut cumul_prob: f64 = 0.0;
        for i in 0..self.weights.len() {
            self.weights[i] = (1.0 - cumul_prob) * rng.gen::<f64>();
            cumul_prob += self.weights[i];
        }
    }

    // generates a uniform weight list.
    fn gen_uniform_weights<R: Rng + ?Sized>(&mut self, rng: &mut R) {
        self.weights = vec![0_f64; self.values.len()];

        for i in 0..self.weights.len() {
            self.weights[i] = rng.gen();
        }
    }

    // Calculates the alias and prob tables use for Vose's alias Method.
    // Algorithm taken from http://www.keithschwarz.com/darts-dice-coins/
    fn gen_tables(&mut self) {
        let n = self.weights.len();
        let sum: f64 = self.weights.iter().sum();

        let mut alias = vec![0_usize; n];
        let mut prob = vec![0_f64; n];

        // multiply each probability by $n$.
        let mut scaled: Vec<f64> = self.weights.iter().map(|f| f * (n as f64) / sum).collect();
        // if $p$ < 1$ add $i$ to $small$.
        let mut small: Vec<usize> = scaled
            .iter()
            .enumerate()
            .filter(|(_, f)| **f < 1.0)
            .map(|(i, _)| i)
            .collect();
        // if $p$ >= 1$ add $i& to $large$.
        let mut large: Vec<usize> = scaled
            .iter()
            .enumerate()
            .filter(|(_, f)| **f >= 1.0)
            .map(|(i, _)| i)
            .collect();

        // While $small$ and $large$ are not empty: ($large$ might be emptied first)
        // remove the first element from $small$ and call it $l$.
        // remove the first element from $large$ and call it $g$.
        // set $prob[l] = p_l$
        // set $alias[l] = g$
        // set $p_g = (p_g+p_l) - 1$ (This is a more numerically stable option)
        // if $p_g < 1$ add $g$ to $small$.
        // otherwise add $g$ to $large$ as %p_g >= 1$
        while !small.is_empty() && !large.is_empty() {
            let l = small.remove(0);
            let g = large.remove(0);

            prob[l] = scaled[l];
            alias[l] = g;

            scaled[g] = scaled[g] + scaled[l] - 1.0;
            if scaled[g] < 1.0 {
                small.push(g);
            } else {
                large.push(g);
            }
        }

        // while $large$ is not empty, remove the first element ($g$) and
        // set $prob[g] = 1$.
        while !large.is_empty() {
            prob[large.remove(0)] = 1.0;
        }

        // while $small$ is not empty, remove the first element ($l$) and
        // set $prob[l] = 1$.
        while !small.is_empty() {
            prob[small.remove(0)] = 1.0;
        }

        self.prob = prob;
        self.alias = alias;
    }
}

impl fmt::Display for WeightedDist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dist = self.0.lock().unwrap();
        write!(f, "{dist}")
    }
}

impl fmt::Display for InnerWeightedDist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf: String = "[ ".into();

        for (i, v) in self.values.iter().enumerate() {
            let p = self.weights[i];
            if p > 0.01 {
                buf.push_str(&format!("{v}: {p}, "));
            }
        }
        write!(f, "]")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::init_subscriber;
    use crate::Result;

    use ptrs::trace;
    use tracing::{span_enabled, Level};

    #[test]
    fn weighted_dist_uniformity() -> Result<()> {
        init_subscriber();
        let seed = drbg::Seed::new()?;

        let n_trials = 1_000_000;
        let mut hist = [0_usize; 1000];

        let w = WeightedDist::new(seed, 0, 999, true);

        if span_enabled!(Level::TRACE) {
            trace!("Table:");
            trace!("{w}");
            let wi = w.0.lock().unwrap();
            let sum: f64 = wi.weights.iter().sum();
            let min_value = wi.min_value;
            let values = &wi.values;

            for (i, weight) in wi.weights.iter().enumerate() {
                let p = weight / sum;
                if p > 0.000001 {
                    // filter out tiny values
                    trace!(" [{}]: {p}", min_value + values[i]);
                }
            }
        }

        for _ in 0..n_trials {
            let idx: usize = w.sample().try_into().unwrap();
            hist[idx] += 1;
        }

        if span_enabled!(Level::TRACE) {
            trace!("Generated:");
            for (val, count) in hist.iter().enumerate() {
                if *count != 0 {
                    trace!(" {val}: {:} ({count})", *count as f64 / n_trials as f64);
                }
            }
        }

        Ok(())
    }
}
