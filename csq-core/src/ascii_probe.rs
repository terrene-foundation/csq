//! Test-only counts at the existing Unicode library call sites.
use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;

thread_local! {
    static COUNTS: Cell<Option<[usize; 2]>> = const { Cell::new(None) };
}

fn index(phase: &str) -> usize {
    match phase {
        "op_unicode_category" => 0,
        "op_nfkc" => 1,
        _ => panic!("unknown ASCII observation phase: {phase}"),
    }
}

pub(crate) fn hit(phase: &str) {
    let index = index(phase);
    COUNTS.with(|counts| {
        if let Some(mut values) = counts.get() {
            values[index] = values[index].saturating_add(1);
            counts.set(Some(values));
        }
    });
}

// Keep the saved thread-local state on its originating thread.
struct Scope(Option<[usize; 2]>, PhantomData<Rc<()>>);

impl Drop for Scope {
    fn drop(&mut self) {
        COUNTS.with(|counts| counts.set(self.0));
    }
}

/// Measure actual calls on this thread and restore the previous scope on unwind.
pub(crate) fn observe<R>(phase: &str, action: impl FnOnce() -> R) -> (R, usize) {
    let index = index(phase);
    let scope = Scope(
        COUNTS.with(|counts| counts.replace(Some([0; 2]))),
        PhantomData,
    );
    let result = action();
    let count = COUNTS.with(|counts| counts.get().expect("active ASCII observation")[index]);
    drop(scope);
    (result, count)
}

#[test]
fn observer_restores_after_return_nested_scope_and_unwind() {
    let before = COUNTS.with(Cell::get);
    let (result, count) = observe("op_unicode_category", || {
        hit("op_unicode_category");
        hit("op_unicode_category");
        let inner = observe("op_nfkc", || {
            for _ in 0..3 {
                hit("op_nfkc");
            }
            7
        });
        assert_eq!(inner, (7, 3));
        let failed = std::panic::catch_unwind(|| {
            observe("op_unicode_category", || {
                for _ in 0..5 {
                    hit("op_unicode_category");
                }
                panic!("owned observation unwind");
            })
        });
        assert!(failed.is_err());
        assert_eq!(COUNTS.with(Cell::get), Some([2, 0]));
        hit("op_unicode_category");
        9
    });
    assert_eq!((result, count), (9, 3));
    assert_eq!(COUNTS.with(Cell::get), before);
}
