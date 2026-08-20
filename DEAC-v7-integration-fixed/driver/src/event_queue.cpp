namespace deac::kernel {

NTSTATUS EventQueue::Initialize() {
    KeInitializeSpinLock(&lock_);
    KeInitializeEvent(&data_event_, NotificationEvent, FALSE);
    head_ = tail_ = count_ = 0; sequence_ = 0; dropped_ = 0;
    return STATUS_SUCCESS;
}

VOID EventQueue::Reset() {
    KIRQL irql; KeAcquireSpinLock(&lock_, &irql);
    head_ = tail_ = count_ = 0; KeClearEvent(&data_event_);
    KeReleaseSpinLock(&lock_, irql);
}

BOOLEAN EventQueue::Push(const deac::protocol::Event& event) {
    KIRQL irql; KeAcquireSpinLock(&lock_, &irql);
    auto copy = event; copy.sequence = ++sequence_;
    if (count_ == Capacity) { tail_ = (tail_ + 1) % Capacity; --count_; ++dropped_; }
    ring_[head_] = copy; head_ = (head_ + 1) % Capacity; ++count_;
    KeSetEvent(&data_event_, IO_NO_INCREMENT, FALSE);
    KeReleaseSpinLock(&lock_, irql); return TRUE;
}

BOOLEAN EventQueue::Pop(deac::protocol::Event* out) {
    if (!out) return FALSE;
    KIRQL irql; KeAcquireSpinLock(&lock_, &irql);
    if (count_ == 0) { KeReleaseSpinLock(&lock_, irql); return FALSE; }
    *out = ring_[tail_]; tail_ = (tail_ + 1) % Capacity; --count_;
    if (count_ == 0) KeClearEvent(&data_event_);
    KeReleaseSpinLock(&lock_, irql); return TRUE;
}

PKEVENT EventQueue::Event() { return &data_event_; }
ULONG EventQueue::Dropped() {
    KIRQL irql; KeAcquireSpinLock(&lock_, &irql);
    const ULONG dropped = dropped_;
    KeReleaseSpinLock(&lock_, irql);
    return dropped;
}

EventQueue g_event_queue;

} // namespace deac::kernel
