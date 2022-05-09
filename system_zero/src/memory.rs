use plonky2::field::extension_field::Extendable;
use plonky2::field::field_types::{Field, PrimeField64};
use plonky2::field::packed_field::PackedField;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use starky::constraint_consumer::{ConstraintConsumer, RecursiveConstraintConsumer};
use starky::vars::{StarkEvaluationTargets, StarkEvaluationVars};

use crate::public_input_layout::NUM_PUBLIC_INPUTS;
use crate::registers::memory::*;
use crate::registers::NUM_COLUMNS;

#[derive(Default)]
pub struct TransactionMemory {
    pub calls: Vec<ContractMemory>,
}

/// A virtual memory space specific to the current contract call.
pub struct ContractMemory {
    pub code: MemorySegment,
    pub main: MemorySegment,
    pub calldata: MemorySegment,
    pub returndata: MemorySegment,
}

pub struct MemorySegment {
    pub content: Vec<u8>,
}

pub(crate) fn generate_memory<F: PrimeField64>(values: &mut [F; NUM_COLUMNS]) {
    todo!()
}

pub(crate) fn eval_memory<F: Field, P: PackedField<Scalar = F>>(
    vars: StarkEvaluationVars<F, P, NUM_COLUMNS, NUM_PUBLIC_INPUTS>,
    yield_constr: &mut ConstraintConsumer<P>,
) {
    let addr_context = vars.local_values[SORTED_MEMORY_ADDR_CONTEXT];
    let addr_segment = vars.local_values[SORTED_MEMORY_ADDR_SEGMENT];
    let addr_virtual = vars.local_values[SORTED_MEMORY_ADDR_VIRTUAL];
    let from = vars.local_values[SORTED_MEMORY_FROM]; // TODO: replace "from" and "to" with "val" and "R/W"
    let to = vars.local_values[SORTED_MEMORY_TO];
    let timestamp = vars.local_values[SORTED_MEMORY_TIMESTAMP];

    let next_addr_context = vars.next_values[SORTED_MEMORY_ADDR_CONTEXT];
    let next_addr_segment = vars.next_values[SORTED_MEMORY_ADDR_SEGMENT];
    let next_addr_virtual = vars.next_values[SORTED_MEMORY_ADDR_VIRTUAL];
    let next_from = vars.next_values[SORTED_MEMORY_FROM];
    let next_to = vars.next_values[SORTED_MEMORY_TO];
    let next_timestamp = vars.next_values[SORTED_MEMORY_TIMESTAMP];

    let trace_context = vars.local_values[MEMORY_TRACE_CONTEXT];
    let trace_segment = vars.local_values[MEMORY_TRACE_SEGMENT];
    let trace_virtual = vars.local_values[MEMORY_TRACE_VIRTUAL];
    let two_traces_combined = vars.local_values[MEMORY_TWO_TRACES_COMBINED];
    let all_traces_combined = vars.local_values[MEMORY_ALL_TRACES_COMBINED];

    let current = vars.local_values[MEMORY_CURRENT];
    let next_current = vars.next_values[MEMORY_CURRENT];

    // First set of ordering constraint: traces are boolean.
    yield_constr.constraint(trace_context * (F::ONE - trace_context));
    yield_constr.constraint(trace_segment * (F::ONE - trace_segment));
    yield_constr.constraint(trace_virtual * (F::ONE - trace_virtual));

    // Second set of ordering constraints: trace matches with no change in corresponding column.
    yield_constr.constraint(trace_context * (next_addr_context - addr_context));
    yield_constr.constraint(trace_segment * (next_addr_segment - addr_segment));
    yield_constr.constraint(trace_virtual * (next_addr_virtual - addr_virtual));

    let context_range_check = vars.local_values[crate::registers::range_check_degree::col_rc_degree_input(0)];
    let segment_range_check = vars.local_values[crate::registers::range_check_degree::col_rc_degree_input(1)];
    let virtual_range_check = vars.local_values[crate::registers::range_check_degree::col_rc_degree_input(2)];

    // Third set of ordering constraints: range-check difference in the column that should be increasing.
    yield_constr.constraint(
        context_range_check
            - trace_context * (next_addr_segment - addr_segment)
            - (F::ONE - trace_context) * (next_addr_context - addr_context - F::ONE),
    );
    yield_constr.constraint(
        segment_range_check
            - trace_segment * (next_addr_virtual - addr_virtual)
            - (F::ONE - trace_segment) * (next_addr_segment - addr_segment - F::ONE),
    );
    yield_constr.constraint(
        virtual_range_check
            - trace_virtual * (next_timestamp - timestamp)
            - (F::ONE - trace_virtual) * (next_addr_virtual - addr_virtual - F::ONE),
    );

    // Helper constraints to get the product of (1 - trace_context), (1 - trace_segment), and (1 - trace_virtual).
    yield_constr
        .constraint(two_traces_combined - (F::ONE - trace_context) * (F::ONE - trace_segment));
    yield_constr.constraint(all_traces_combined - two_traces_combined * (F::ONE - trace_virtual));

    // Enumerate purportedly-ordered log using current value c.
    yield_constr.constraint_first_row(current);
    yield_constr.constraint(current - from);
    yield_constr.constraint(next_current - all_traces_combined * to);
}

pub(crate) fn eval_memory_recursively<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    vars: StarkEvaluationTargets<D, NUM_COLUMNS, NUM_PUBLIC_INPUTS>,
    yield_constr: &mut RecursiveConstraintConsumer<F, D>,
) {
    let one = builder.one_extension();

    let addr_context = vars.local_values[SORTED_MEMORY_ADDR_CONTEXT];
    let addr_segment = vars.local_values[SORTED_MEMORY_ADDR_SEGMENT];
    let addr_virtual = vars.local_values[SORTED_MEMORY_ADDR_VIRTUAL];
    let from = vars.local_values[SORTED_MEMORY_FROM]; // TODO: replace "from" and "to" with "val" and "R/W"
    let to = vars.local_values[SORTED_MEMORY_TO];
    let timestamp = vars.local_values[SORTED_MEMORY_TIMESTAMP];

    let next_addr_context = vars.next_values[SORTED_MEMORY_ADDR_CONTEXT];
    let next_addr_segment = vars.next_values[SORTED_MEMORY_ADDR_SEGMENT];
    let next_addr_virtual = vars.next_values[SORTED_MEMORY_ADDR_VIRTUAL];
    let next_from = vars.next_values[SORTED_MEMORY_FROM];
    let next_to = vars.next_values[SORTED_MEMORY_TO];
    let next_timestamp = vars.next_values[SORTED_MEMORY_TIMESTAMP];

    let trace_context = vars.local_values[MEMORY_TRACE_CONTEXT];
    let trace_segment = vars.local_values[MEMORY_TRACE_SEGMENT];
    let trace_virtual = vars.local_values[MEMORY_TRACE_VIRTUAL];
    let two_traces_combined = vars.local_values[MEMORY_TWO_TRACES_COMBINED];
    let all_traces_combined = vars.local_values[MEMORY_ALL_TRACES_COMBINED];

    let current = vars.local_values[MEMORY_CURRENT];
    let next_current = vars.next_values[MEMORY_CURRENT];

    let not_trace_context = builder.sub_extension(one, trace_context);
    let not_trace_segment = builder.sub_extension(one, trace_segment);
    let not_trace_virtual = builder.sub_extension(one, trace_virtual);
    let addr_context_diff = builder.sub_extension(next_addr_context, addr_context);
    let addr_segment_diff = builder.sub_extension(next_addr_segment, addr_segment);
    let addr_virtual_diff = builder.sub_extension(next_addr_virtual, addr_virtual);
    let timestamp_diff = builder.sub_extension(next_timestamp, timestamp);

    // First set of ordering constraint: traces are boolean.
    yield_constr.constraint(builder, builder.mul_extension(trace_context, not_trace_context));
    yield_constr.constraint(builder, builder.mul_extension(trace_segment, not_trace_segment));
    yield_constr.constraint(builder, builder.mul_extension(trace_virtual, not_trace_virtual));

    // Second set of ordering constraints: trace matches with no change in corresponding column.
    yield_constr.constraint(builder, builder.mul_extension(trace_context, addr_context_diff));
    yield_constr.constraint(builder, builder.mul_extension(trace_segment, addr_segment_diff));
    yield_constr.constraint(builder, builder.mul_extension(trace_virtual, addr_virtual_diff));
    
    let context_range_check = vars.local_values[crate::registers::range_check_degree::col_rc_degree_input(0)];
    let segment_range_check = vars.local_values[crate::registers::range_check_degree::col_rc_degree_input(1)];
    let virtual_range_check = vars.local_values[crate::registers::range_check_degree::col_rc_degree_input(2)];

    // Third set of ordering constraints: range-check difference in the column that should be increasing.
    let diff_if_context_equal = builder.mul_extension(trace_context, addr_segment_diff);
    let addr_context_diff_min_one = builder.sub_extension(addr_context_diff, one);
    let diff_if_context_unequal = builder.mul_extension(not_trace_context, addr_context_diff_min_one);
    let sum_of_diffs_context = builder.sub_extension(diff_if_context_equal, diff_if_context_unequal);
    yield_constr.constraint(builder, builder.sub_extension(context_range_check, sum_of_diffs_context));

    let diff_if_segment_equal = builder.mul_extension(trace_segment, addr_virtual_diff);
    let addr_segment_diff_min_one = builder.sub_extension(addr_segment_diff, one);
    let diff_if_segment_unequal = builder.mul_extension(not_trace_segment, addr_segment_diff_min_one);
    let sum_of_diffs_segment = builder.sub_extension(diff_if_segment_equal, diff_if_segment_unequal);
    yield_constr.constraint(builder, builder.sub_extension(segment_range_check, sum_of_diffs_segment));

    let diff_if_virtual_equal = builder.mul_extension(trace_virtual, timestamp_diff);
    let addr_virtual_diff_min_one = builder.sub_extension(addr_virtual_diff, one);
    let diff_if_virtual_unequal = builder.mul_extension(not_trace_virtual, addr_virtual_diff_min_one);
    let sum_of_diffs_virtual = builder.sub_extension(diff_if_virtual_equal, diff_if_virtual_unequal);
    yield_constr.constraint(builder, builder.sub_extension(virtual_range_check, sum_of_diffs_virtual));

    // Helper constraints to get the product of (1 - trace_context), (1 - trace_segment), and (1 - trace_virtual).
    let expected_two_traces_combined = builder.mul_extension(not_trace_context, not_trace_segment);
    yield_constr.constraint(builder, builder.sub_extension(two_traces_combined, expected_two_traces_combined));
    let expected_all_traces_combined = builder.mul_extension(expected_two_traces_combined, not_trace_virtual)
    yield_constr.constraint(builder, builder.sub_extension(all_traces_combined, expected_all_traces_combined));

    // Enumerate purportedly-ordered log using current value c.
    yield_constr.constraint_first_row(builder, current);
    yield_constr.constraint(builder, builder.sub_extension(current, from));
    let expected_next_current = builder.mul_extension(all_traces_combined, to);
    yield_constr.constraint(builder, builder.sub_extension(next_current, expected_next_current));
}
