---
layout: page
title: QEMU 4.1与KVM的初始化与运行循环
modified: 2019-12-11
---

## 版本
QEMU版本：4.1.0
KVM/Linux kernel版本：4.20.17
## QEMU/KVM初始化过程，QEMU部分
![](images/QEMU/init.png)
vl.c文件是QEMU的main函数所在的文件，main函数是qemu的入口，在函数的开始会有一个大循环负责解析命令行参数。之后QEMU的初始化主要分三个阶段，中间会穿插一些设备的初始化。
### 内存布局的初始化
内存布局初始化函数为cpu_exec_init_all()，该函数在早起版本QEMU中也负责讲bootloader和内核等加载入内存，在现在的版本中，该函数只负责初始化客户机物理内存布局和IO布局和注册操作函数。
```c
void cpu_exec_init_all(void)
{
    qemu_mutex_init(&ram_list.mutex);
    /* The data structures we set up here depend on knowing the page size,
     * so no more changes can be made after this point.
     * In an ideal world, nothing we did before we had finished the
     * machine setup would care about the target page size, and we could
     * do this much later, rather than requiring board models to state
     * up front what their requirements are.
     */
    finalize_target_page_bits();
    io_mem_init();
    memory_map_init();
    qemu_mutex_init(&map_client_list_lock);
}
```
### KVM初始化
configure_accelerator()负责初始化kvm。这个函数会根据配置文件或者命令行参数初始化对应的acce，包括tcg、kvm、xen。该函数调用accel_init_machine()，这个函数又调用对应类的init_machine方法。
```c
for (tmp = accel_list; !accel_initialised && tmp && *tmp; tmp++) {
        acc = accel_find(*tmp);
        if (!acc) {
            continue;
        }
        ret = accel_init_machine(acc, ms);
        if (ret < 0) {
            init_failed = true;
            error_report("failed to initialize %s: %s",
                         acc->name, strerror(-ret));
        } else {
            accel_initialised = true;
        }
    }
```
```c
static int accel_init_machine(AccelClass *acc, MachineState *ms)
{
    ObjectClass *oc = OBJECT_CLASS(acc);
    const char *cname = object_class_get_name(oc);
    AccelState *accel = ACCEL(object_new(cname));
    int ret;
    ms->accelerator = accel;
    *(acc->allowed) = true;
    ret = acc->init_machine(ms);
    if (ret < 0) {
        ms->accelerator = NULL;
        *(acc->allowed) = false;
        object_unref(OBJECT(accel));
    } else {
        object_set_accelerator_compat_props(acc->compat_props);
    }
    return ret;
}
```
在kvm部分中，init_machine方法是kvm-all.c中的kvm_init()函数，这个函数很长，他的主要功能是使用ioctl通知kvm创建一个新的vm，确定kvm所支持的功能符合qemu所需要的功能需求，注册内存和IO事件通知回调函数。
```c
s->vmfd = -1;
    s->fd = qemu_open("/dev/kvm", O_RDWR);
    if (s->fd == -1) {
        fprintf(stderr, "Could not access KVM kernel module: %m\n");
        ret = -errno;
        goto err;
    }

    ret = kvm_ioctl(s, KVM_GET_API_VERSION, 0);
    if (ret < KVM_API_VERSION) {
        if (ret >= 0) {
            ret = -EINVAL;
        }
        fprintf(stderr, "kvm version too old\n");
        goto err;
    }

    if (ret > KVM_API_VERSION) {
        ret = -EINVAL;
        fprintf(stderr, "kvm version not supported\n");
        goto err;
    }

    kvm_immediate_exit = kvm_check_extension(s, KVM_CAP_IMMEDIATE_EXIT);
    s->nr_slots = kvm_check_extension(s, KVM_CAP_NR_MEMSLOTS);
    
....
 do {
        ret = kvm_ioctl(s, KVM_CREATE_VM, type);
    } while (ret == -EINTR);
```
这个函数最后会调用kvm_arch_init()去进行一些架构特有的初始化，这个函数在x86中是target/i386/kvm.c中的kvm_arch_init()。在x86中这个函数主要是设置EPT支持等x86虚拟化架构特有的功能。
### 主机初始化
这部分是工作最多，最复杂的初始化部分。这部分的功能主要包括创建并初始化vCPU、加载bootloader、kernel等到虚拟机物理内存，初始化总线等。这部分代码入口函数是machine_run_board_init()，这个函数的调用是main函数初始化部分最后的几个，之初始化就完成了。
```c
void machine_run_board_init(MachineState *machine)
{
    MachineClass *machine_class = MACHINE_GET_CLASS(machine);

    numa_complete_configuration(machine);
    if (nb_numa_nodes) {
        machine_numa_finish_cpu_init(machine);
    }

    /* If the machine supports the valid_cpu_types check and the user
     * specified a CPU with -cpu check here that the user CPU is supported.
     */
    if (machine_class->valid_cpu_types && machine->cpu_type) {
        ObjectClass *class = object_class_by_name(machine->cpu_type);
        int i;

        for (i = 0; machine_class->valid_cpu_types[i]; i++) {
            if (object_class_dynamic_cast(class,
                                          machine_class->valid_cpu_types[i])) {
                /* The user specificed CPU is in the valid field, we are
                 * good to go.
                 */
                break;
            }
        }

        if (!machine_class->valid_cpu_types[i]) {
            /* The user specified CPU is not valid */
            error_report("Invalid CPU type: %s", machine->cpu_type);
            error_printf("The valid types are: %s",
                         machine_class->valid_cpu_types[0]);
            for (i = 1; machine_class->valid_cpu_types[i]; i++) {
                error_printf(", %s", machine_class->valid_cpu_types[i]);
            }
            error_printf("\n");

            exit(1);
        }
    }

    machine_class->init(machine);
}
```
这个函数最终会调用machine_class的init方法。这个方法在x86上的实现是hw/i386/pc_piix.c中的pc_init1()。这个函数非常长与复杂，这里我们关心两部分内容。
#### vCPU初始化
```c
pc_cpus_init(pcms);

    if (kvm_enabled() && pcmc->kvmclock_enabled) {
        kvmclock_create();
    }
```
调用pc_cpus_init()进行vcpu的创建和初始化。这个函数会调用pc_new_cpu()创建规定数量的vCPU。pc_new_cpu()最终将调用x86_cpu_realizefn(),这个函数又会调用qemu_init_vcpu()。qemu_init_vcpu()中会创建一个线程，线程函数为qemu_kvm_cpu_thread_fn()，这将是之后gust实际执行的时候的函数。qemu_kvm_cpu_thread_fn()开始会调用kvm_init_vcpu(),这个函数会使用ioctl通知kvm创建新vcpu。kvm_init_vcpu()又会调用kvm_arch_init_vcpu()对vCPU进行架构特定的初始化。
#### 镜像加载
pc_memory_init()在非xen的情况下将被调用，这个函数将具体的初始化内存和IO的各个区域并调用bochs_bios_init和load_linux加载内核。
## 运行
![](images/QEMU/run.png)
### QEMU
之前创建的线程中有一个大循环，执行kvm_cpu_exec()
```c
do {
        if (cpu_can_run(cpu)) {
            r = kvm_cpu_exec(cpu);
            if (r == EXCP_DEBUG) {
                cpu_handle_guest_debug(cpu);
            }
        }
        qemu_wait_io_event(cpu);
    } while (!cpu->unplug || cpu_can_run(cpu));
```
kvm_cpu_exec()函数会调用ioctl让kvm执行客户机代码，一直到在需要进行IO模拟等操作。此时从内核返回，由qemu处理这些操作，之后返回kvm继续执行。
### KVM
在qemu通过ioctl进入内核后，将进入kvm_arch_vcpu_ioctl_run函数。
```c
	vcpu_load(vcpu);
	kvm_sigset_activate(vcpu);
	kvm_load_guest_fpu(vcpu);
...
if (kvm_run->immediate_exit)
		r = -EINTR;
	else
		r = vcpu_run(vcpu);
```
这个函数将调用vcpu_run，vcpu_run中存在一个大循环
```c
for (;;) {
		if (kvm_vcpu_running(vcpu)) {
			r = vcpu_enter_guest(vcpu);
		} else {
			r = vcpu_block(kvm, vcpu);
		}

		if (r <= 0)
			break;

		kvm_clear_request(KVM_REQ_PENDING_TIMER, vcpu);
		if (kvm_cpu_has_pending_timer(vcpu))
			kvm_inject_pending_timer_irqs(vcpu);

		if (dm_request_for_irq_injection(vcpu) &&
			kvm_vcpu_ready_for_interrupt_injection(vcpu)) {
			r = 0;
			vcpu->run->exit_reason = KVM_EXIT_IRQ_WINDOW_OPEN;
			++vcpu->stat.request_irq_exits;
			break;
		}

		kvm_check_async_pf_completion(vcpu);

		if (signal_pending(current)) {
			r = -EINTR;
			vcpu->run->exit_reason = KVM_EXIT_INTR;
			++vcpu->stat.signal_exits;
			break;
		}
		if (need_resched()) {
			srcu_read_unlock(&kvm->srcu, vcpu->srcu_idx);
			cond_resched();
			vcpu->srcu_idx = srcu_read_lock(&kvm->srcu);
		}
	}
```
在大循环中，将调用vcpu_enter_guest。vcpu_enter_guest代码也很长，会调用kvm_x86_ops->run，为开始客户机执行做准备，这个方法的实现是vmx_vcpu_run，最终将调用____vmx_vcpu_run，该函数实际上是一个汇编写的trampoline。而在vcpu_enter_guest退出时，将调用kvm_x86_ops->handle_exit(vcpu)处理。
```c
static int (*kvm_vmx_exit_handlers[])(struct kvm_vcpu *vcpu) = {
[EXIT_REASON_EXCEPTION_NMI]           = handle_exception,
[EXIT_REASON_EXTERNAL_INTERRUPT]      = handle_external_interrupt,
[EXIT_REASON_TRIPLE_FAULT]            = handle_triple_fault,
[EXIT_REASON_NMI_WINDOW]      = handle_nmi_window,
[EXIT_REASON_IO_INSTRUCTION]          = handle_io,
[EXIT_REASON_CR_ACCESS]               = handle_cr,
[EXIT_REASON_DR_ACCESS]               = handle_dr,
[EXIT_REASON_CPUID]                   = handle_cpuid,
[EXIT_REASON_MSR_READ]                = handle_rdmsr,
[EXIT_REASON_MSR_WRITE]               = handle_wrmsr,
[EXIT_REASON_PENDING_INTERRUPT]       = handle_interrupt_window,
[EXIT_REASON_HLT]                     = handle_halt,
[EXIT_REASON_INVD]      = handle_invd,
[EXIT_REASON_INVLPG]      = handle_invlpg,
[EXIT_REASON_VMCALL]                  = handle_vmcall,
[EXIT_REASON_VMCLEAR]              = handle_vmx_insn,
[EXIT_REASON_VMLAUNCH]                = handle_vmx_insn,
[EXIT_REASON_VMPTRLD]                 = handle_vmx_insn,
[EXIT_REASON_VMPTRST]                 = handle_vmx_insn,
[EXIT_REASON_VMREAD]                  = handle_vmx_insn,
[EXIT_REASON_VMRESUME]                = handle_vmx_insn,
[EXIT_REASON_VMWRITE]                 = handle_vmx_insn,
[EXIT_REASON_VMOFF]                   = handle_vmx_insn,
[EXIT_REASON_VMON]                    = handle_vmx_insn,
[EXIT_REASON_TPR_BELOW_THRESHOLD]     = handle_tpr_below_threshold,
[EXIT_REASON_APIC_ACCESS]             = handle_apic_access,
[EXIT_REASON_WBINVD]                  = handle_wbinvd,
[EXIT_REASON_XSETBV]                  = handle_xsetbv,
[EXIT_REASON_TASK_SWITCH]             = handle_task_switch,
[EXIT_REASON_MCE_DURING_VMENTRY]      = handle_machine_check,
[EXIT_REASON_EPT_VIOLATION]      = handle_ept_violation,
[EXIT_REASON_EPT_MISCONFIG]           = handle_ept_misconfig,
[EXIT_REASON_PAUSE_INSTRUCTION]       = handle_pause,
[EXIT_REASON_MWAIT_INSTRUCTION]      = handle_invalid_op,
[EXIT_REASON_MONITOR_INSTRUCTION]     = handle_invalid_op,
};
```