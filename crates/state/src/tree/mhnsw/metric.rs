// Path: crates/state/src/tree/mhnsw/metric.rs

use serde::{Deserialize, Serialize};

/// A dense float vector.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vector(pub Vec<f32>);

pub trait DistanceMetric: Send + Sync + Clone + 'static {
    fn distance(&self, a: &Vector, b: &Vector) -> f32;
}

#[derive(Clone, Debug, Default)]
pub struct Euclidean;

impl DistanceMetric for Euclidean {
    fn distance(&self, a: &Vector, b: &Vector) -> f32 {
        a.0.iter()
            .zip(b.0.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f32>()
            .sqrt()
    }
}

#[derive(Clone, Debug, Default)]
pub struct CosineSimilarity;

impl DistanceMetric for CosineSimilarity {
    fn distance(&self, a: &Vector, b: &Vector) -> f32 {
        let dot: f32 = a.0.iter().zip(b.0.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.0.iter().map(|x| x.powi(2)).sum::<f32>().sqrt();
        let norm_b: f32 = b.0.iter().map(|x| x.powi(2)).sum::<f32>().sqrt();
        
        if norm_a == 0.0 || norm_b == 0.0 {
            return 1.0;
        }
        
        // Convert similarity (1.0 is best) to distance (0.0 is best)
        1.0 - (dot / (norm_a * norm_b))
    }
}