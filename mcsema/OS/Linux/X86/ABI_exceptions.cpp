namespace __cxxabiv1 {}

#include <unwind.h>

#include <cstddef>
#include <cstdint>
#include <typeinfo>
using namespace __cxxabiv1;
extern "C" {
void *__cxa_allocate_exception(size_t thrown_size);
void __cxa_free_exception(void *thrown_exception);
void *__cxa_allocate_dependent_exception();
void __cxa_free_dependent_exception(void *dependent_exception);
void __cxa_throw(void *thrown_exception, class std::type_info *tinfo,
                 void (*dest)(void *));
void *__cxa_get_exception_ptr(void *exceptionObject);
void *__cxa_begin_catch(void *exceptionObject);
void __cxa_end_catch();
std::type_info *__cxa_current_exception_type();
void __cxa_rethrow();
void *__cxa_current_primary_exception();
void __cxa_decrement_exception_refcount(void *primary_exception);
struct __cxa_eh_globals;
__cxa_eh_globals *__cxa_get_globals();
__cxa_eh_globals *__cxa_get_globals_fast();
void __cxa_increment_exception_refcount(void *primary_exception);
void __cxa_rethrow_primary_exception(void *primary_exception);
bool __cxa_uncaught_exception();
_Unwind_Reason_Code
__gxx_personality_v0(int, _Unwind_Action, _Unwind_Exception_Class,
                     struct _Unwind_Exception *, struct _Unwind_Context *);
int __cxa_guard_acquire(uint64_t *guard_object);
void __cxa_guard_release(uint64_t *);
void __cxa_guard_abort(uint64_t *);
void *__cxa_vec_new(size_t element_count, size_t element_size,
                    size_t padding_size, void (*constructor)(void *),
                    void (*destructor)(void *));
void *__cxa_vec_new2(size_t element_count, size_t element_size,
                     size_t padding_size, void (*constructor)(void *),
                     void (*destructor)(void *), void *(*alloc)(size_t),
                     void (*dealloc)(void *));
void *__cxa_vec_new3(size_t element_count, size_t element_size,
                     size_t padding_size, void (*constructor)(void *),
                     void (*destructor)(void *), void *(*alloc)(size_t),
                     void (*dealloc)(void *, size_t));
void __cxa_vec_ctor(void *array_address, size_t element_count,
                    size_t element_size, void (*constructor)(void *),
                    void (*destructor)(void *));
void __cxa_vec_dtor(void *array_address, size_t element_count,
                    size_t element_size, void (*destructor)(void *));
void __cxa_vec_cleanup(void *array_address, size_t element_count,
                       size_t element_size, void (*destructor)(void *));
void __cxa_vec_delete(void *array_address, size_t element_size,
                      size_t padding_size, void (*destructor)(void *));
void __cxa_vec_delete2(void *array_address, size_t element_size,
                       size_t padding_size, void (*destructor)(void *),
                       void (*dealloc)(void *));
void __cxa_vec_delete3(void *__array_address, size_t element_size,
                       size_t padding_size, void (*destructor)(void *),
                       void (*dealloc)(void *, size_t));
void __cxa_vec_cctor(void *dest_array, void *src_array, size_t element_count,
                     size_t element_size, void (*constructor)(void *, void *),
                     void (*destructor)(void *));
void (*__cxa_new_handler)();
void (*__cxa_terminate_handler)();
void (*__cxa_unexpected_handler)();
void __cxa_bad_cast() __attribute__((noreturn));
void __cxa_bad_typeid() __attribute__((noreturn));
void __cxa_pure_virtual(void);
void __cxa_call_unexpected(void *) __attribute__((noreturn));
char *__cxa_demangle(const char *mangled_name, char *output_buffer,
                     size_t *length, int *status);
void *__dynamic_cast(const void *__src_ptr, const __class_type_info *__src_type,
                     const __class_type_info *__dst_type, ptrdiff_t __src2dst);
void _Unwind_Resume(struct _Unwind_Exception *object);
int __cxa_atexit(void (*f)(void *), void *p, void *d);

void *malloc(size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);
void *memset(void *str, int c, size_t n);
}  // extern C

__attribute__((used)) void *__mcsema_externs[] = {
    reinterpret_cast<void *>(__cxa_allocate_exception),
    reinterpret_cast<void *>(__cxa_free_exception),
    reinterpret_cast<void *>(__cxa_allocate_dependent_exception),
    reinterpret_cast<void *>(__cxa_free_dependent_exception),
    reinterpret_cast<void *>(__cxa_throw),
    reinterpret_cast<void *>(__cxa_get_exception_ptr),
    reinterpret_cast<void *>(__cxa_begin_catch),
    reinterpret_cast<void *>(__cxa_end_catch),
    reinterpret_cast<void *>(__cxa_current_exception_type),
    reinterpret_cast<void *>(__cxa_rethrow),
    reinterpret_cast<void *>(__cxa_current_primary_exception),
    reinterpret_cast<void *>(__cxa_decrement_exception_refcount),
    reinterpret_cast<void *>(__cxa_get_globals),
    reinterpret_cast<void *>(__cxa_get_globals_fast),
    reinterpret_cast<void *>(__cxa_increment_exception_refcount),
    reinterpret_cast<void *>(__cxa_rethrow_primary_exception),
    reinterpret_cast<void *>(__cxa_uncaught_exception),
    reinterpret_cast<void *>(__cxa_guard_acquire),
    reinterpret_cast<void *>(__cxa_guard_release),
    reinterpret_cast<void *>(__cxa_guard_abort),
    reinterpret_cast<void *>(__cxa_vec_new),
    reinterpret_cast<void *>(__cxa_vec_new2),
    reinterpret_cast<void *>(__cxa_vec_new3),
    reinterpret_cast<void *>(__cxa_vec_ctor),
    reinterpret_cast<void *>(__cxa_vec_dtor),
    reinterpret_cast<void *>(__cxa_vec_cleanup),
    reinterpret_cast<void *>(__cxa_vec_delete),
    reinterpret_cast<void *>(__cxa_vec_delete2),
    reinterpret_cast<void *>(__cxa_vec_delete3),
    reinterpret_cast<void *>(__cxa_vec_cctor),
    reinterpret_cast<void *>(__cxa_new_handler),
    reinterpret_cast<void *>(__cxa_terminate_handler),
    reinterpret_cast<void *>(__cxa_unexpected_handler),
    reinterpret_cast<void *>(__cxa_bad_cast),
    reinterpret_cast<void *>(__cxa_bad_typeid),
    reinterpret_cast<void *>(__cxa_pure_virtual),
    reinterpret_cast<void *>(__cxa_call_unexpected),
    reinterpret_cast<void *>(__cxa_demangle),
    reinterpret_cast<void *>(__cxa_atexit),
    reinterpret_cast<void *>(_Unwind_Resume),
    reinterpret_cast<void *>(malloc),
    reinterpret_cast<void *>(realloc),
    reinterpret_cast<void *>(free),
    reinterpret_cast<void *>(memset),
};
