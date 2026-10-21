//! Instantiate one native implementation against a closed, concrete family.
//! Expected/Prepared and AIR/layout are lexical host types, never runtime choices
//! or external callbacks. Both namespaces keep their own fixed wire identity.
macro_rules! instantiate_fixed_dense_backend {
    () => {
        mod assessment {
            include!("../dense_data_inventory/assessment.rs");
        }
        mod native {
            include!("../dense_data_inventory/native.rs");
        }
        mod native_setup {
            include!("../dense_data_inventory/native_setup.rs");
        }
        mod native_wire {
            include!("../dense_data_inventory/native_wire.rs");
        }
    };
}
pub(super) use instantiate_fixed_dense_backend;
