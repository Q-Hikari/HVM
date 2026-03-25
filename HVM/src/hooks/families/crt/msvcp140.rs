use crate::hooks::base::{CallConv, HookDefinition, HookLibrary};
use crate::hooks::registry::HookRegistry;

const EXPORTS: &[&str] = &[
    "??0?$basic_ios@DU?$char_traits@D@std@@@std@@IEAA@XZ",
    "??0?$basic_iostream@DU?$char_traits@D@std@@@std@@QEAA@PEAV?$basic_streambuf@DU?$char_traits@D@std@@@1@@Z",
    "??0?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAA@XZ",
    "??0_Locinfo@std@@QEAA@PEBD@Z",
    "??0_Lockit@std@@QEAA@H@Z",
    "??0ctype_base@std@@QEAA@_K@Z",
    "??1?$basic_ios@DU?$char_traits@D@std@@@std@@UEAA@XZ",
    "??1?$basic_iostream@DU?$char_traits@D@std@@@std@@UEAA@XZ",
    "??1?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAA@XZ",
    "??1_Locinfo@std@@QEAA@XZ",
    "??1_Lockit@std@@QEAA@XZ",
    "??1ctype_base@std@@UEAA@XZ",
    "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEAH@Z",
    "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEA_J@Z",
    "??5?$basic_istream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@AEA_K@Z",
    "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@G@Z",
    "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@H@Z",
    "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAV01@AEAV01@@Z@Z",
    "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAVios_base@1@AEAV21@@Z@Z",
    "??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_K@Z",
    "??Bid@locale@std@@QEAA_KXZ",
    "?_BADOFF@std@@3_JB",
    "?_Decref@facet@locale@std@@UEAAPEAV_Facet_base@3@XZ",
    "?_Getctype@_Locinfo@std@@QEBA?AU_Ctypevec@@XZ",
    "?_Getcvt@_Locinfo@std@@QEBA?AU_Cvtvec@@XZ",
    "?_Getgloballocale@locale@std@@CAPEAV_Locimp@12@XZ",
    "?_Incref@facet@locale@std@@UEAAXXZ",
    "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z",
    "?_Ipfx@?$basic_istream@DU?$char_traits@D@std@@@std@@QEAA_N_N@Z",
    "?_Lock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ",
    "?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ",
    "?_Random_device@std@@YAIXZ",
    "?_Throw_C_error@std@@YAXH@Z",
    "?_Throw_Cpp_error@std@@YAXH@Z",
    "?_Unlock@?$basic_streambuf@DU?$char_traits@D@std@@@std@@UEAAXXZ",
    "?_Xbad_alloc@std@@YAXXZ",
    "?_Xbad_function_call@std@@YAXXZ",
    "?_Xlength_error@std@@YAXPEBD@Z",
    "?_Xout_of_range@std@@YAXPEBD@Z",
    "?flush@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@XZ",
    "?gbump@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXH@Z",
    "?imbue@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAXAEBVlocale@2@@Z",
    "?pbump@?$basic_streambuf@DU?$char_traits@D@std@@@std@@IEAAXH@Z",
    "?put@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV12@D@Z",
    "?sbumpc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ",
    "?setbuf@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAPEAV12@PEAD_J@Z",
    "?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z",
    "?sgetc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ",
    "?showmanyc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JXZ",
    "?snextc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHXZ",
    "?sputc@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAAHD@Z",
    "?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z",
    "?sync@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ",
    "?uflow@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAAHXZ",
    "?uncaught_exception@std@@YA_NXZ",
    "?widen@?$basic_ios@DU?$char_traits@D@std@@@std@@QEBADD@Z",
    "?xsgetn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEAD_J@Z",
    "?xsputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@MEAA_JPEBD_J@Z",
    "_Cnd_destroy",
    "_Cnd_destroy_in_situ",
    "_Cnd_do_broadcast_at_thread_exit",
    "_Cnd_init",
    "_Cnd_init_in_situ",
    "_Cnd_signal",
    "_Cnd_timedwait",
    "_Cnd_wait",
    "_Mtx_current_owns",
    "_Mtx_destroy",
    "_Mtx_destroy_in_situ",
    "_Mtx_init",
    "_Mtx_init_in_situ",
    "_Mtx_lock",
    "_Mtx_unlock",
    "_Query_perf_counter",
    "_Query_perf_frequency",
    "_Thrd_detach",
    "_Thrd_id",
    "_Thrd_join",
    "_Thrd_sleep",
    "_Thrd_start",
    "_Tolower",
    "_Toupper",
    "_Xtime_get_ticks",
];

#[derive(Debug, Default, Clone, Copy)]
pub struct Msvcp140HookLibrary;

impl HookLibrary for Msvcp140HookLibrary {
    fn collect(&self) -> Vec<HookDefinition> {
        EXPORTS
            .iter()
            .map(|function| HookDefinition {
                module: "msvcp140.dll",
                function,
                argc: 0,
                call_conv: CallConv::Win64,
            })
            .collect()
    }
}

pub fn register_msvcp140_hooks(registry: &mut HookRegistry) {
    registry.register_library(&Msvcp140HookLibrary);
}
