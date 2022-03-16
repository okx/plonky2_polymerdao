use std::collections::HashMap;
use std::hash::Hash;
use std::iter::repeat;

/// Converts a slice to a "hash bag", i.e. a `HashMap` whose values correspond to the number of
/// times each value appears in the given `Vec`.
pub(crate) fn create_hash_bag<T: Eq + Hash + Clone>(values: &[T]) -> HashMap<T, usize> {
    let mut counts = HashMap::new();
    for v in values {
        counts.entry(v.clone()).and_modify(|c| *c += 1).or_insert(1);
    }
    counts
}

/// Convert a "hash bag" to a flat `Vec` of values.
///
/// The resulting ordering is undefined, except that multiple instances the same value are
/// guaranteed to be grouped together.
pub(crate) fn flatten_hash_bag<T: Clone>(count_map: &HashMap<T, usize>) -> Vec<T> {
    count_map
        .iter()
        .flat_map(|(val, &count)| repeat(val.clone()).take(count))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use std::collections::HashMap;

    use plonky2::field::field_types::Field;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use rand::{thread_rng, Rng};

    use crate::util::{create_hash_bag, flatten_hash_bag};

    #[test]
    fn test_bag() {
        type F = GoldilocksField;
        let mut rng = thread_rng();
        let n = 1 << 20;
        let t: Vec<F> = (0..n).map(|_| F::rand()).collect();
        // let mut t: Vec<F> = (0..n).map(|i| F::from_canonical_usize(i)).collect();
        // for i in 1 << 16..n {
        //     t[i] = F::from_canonical_usize((1 << 16) - 1);
        // }
        let v: Vec<F> = (0..n).map(|_| t[rng.gen_range(0..n)]).collect();

        let now = std::time::Instant::now();
        let bags = create_hash_bag(&v);
        let permuted_inputs = flatten_hash_bag(&bags);
        let mut unused_table_vals = t.iter().filter(|v| !bags.contains_key(v)).copied();
        let mut permuted_table = Vec::with_capacity(n);
        permuted_table.push(permuted_inputs[0]);
        for i in 1..n {
            let is_repeat = permuted_inputs[i] == permuted_inputs[i - 1];
            permuted_table.push(if is_repeat {
                unused_table_vals
                    .next()
                    .expect("No more unused table values; this should never happen")
            } else {
                permuted_inputs[i]
            });
        }
        dbg!(now.elapsed().as_secs_f64());

        let to_multiset = |l: &[_]| {
            l.iter()
                .fold(HashMap::new(), |mut acc: HashMap<_, usize>, &x| {
                    *acc.entry(x).or_default() += 1;
                    acc
                })
        };
        assert_eq!(to_multiset(&permuted_table), to_multiset(&t));
        assert_eq!(permuted_inputs[0], permuted_table[0]);
        for i in 1..n {
            if permuted_inputs[i] != permuted_inputs[i - 1] {
                assert_eq!(permuted_inputs[i], permuted_table[i]);
            }
        }
    }

    #[test]
    fn test_sorting() {
        type F = GoldilocksField;
        let mut rng = thread_rng();
        let n = 1 << 20;
        let mut t: Vec<F> = (0..n).map(|_| F::rand()).collect();
        // let mut t: Vec<F> = (0..n).map(|i| F::from_canonical_usize(i)).collect();
        // for i in 1 << 16..n {
        //     t[i] = F::from_canonical_usize((1 << 16) - 1);
        // }
        let v: Vec<F> = (0..n).map(|_| t[rng.gen_range(0..n)]).collect();

        t.sort_unstable();
        let now = std::time::Instant::now();
        let mut permuted_inputs = v.clone();
        permuted_inputs.sort_unstable();
        dbg!(now.elapsed().as_secs_f64());
        let mut unused_table_inds = Vec::with_capacity(n);
        let mut unused_table_vals = Vec::with_capacity(n);
        let mut permuted_table = vec![F::ZERO; n];
        let mut i = 0;
        let mut j = 0;
        while (j < n) && (i < n) {
            match permuted_inputs[i].cmp(&t[j]) {
                Ordering::Greater => {
                    unused_table_vals.push(t[j]);
                    j += 1;
                }
                Ordering::Less => {
                    if let Some(x) = unused_table_vals.pop() {
                        permuted_table[i] = x;
                    } else {
                        unused_table_inds.push(i);
                    }
                    i += 1;
                }
                Ordering::Equal => {
                    permuted_table[i] = t[j];
                    i += 1;
                    j += 1;
                }
            }
        }
        for jj in j..n {
            unused_table_vals.push(t[jj]);
        }
        for ii in i..n {
            unused_table_inds.push(ii);
        }
        for (ind, val) in unused_table_inds.into_iter().zip(unused_table_vals) {
            permuted_table[ind] = val;
        }
        dbg!(now.elapsed().as_secs_f64());
        let to_multiset = |l: &[_]| {
            l.iter()
                .fold(HashMap::new(), |mut acc: HashMap<_, usize>, &x| {
                    *acc.entry(x).or_default() += 1;
                    acc
                })
        };

        assert_eq!(to_multiset(&permuted_table), to_multiset(&t));
        assert_eq!(permuted_inputs[0], permuted_table[0]);
        for i in 1..n {
            if permuted_inputs[i] != permuted_inputs[i - 1] {
                assert_eq!(permuted_inputs[i], permuted_table[i]);
            }
        }
    }
}
