// Stub for ___chkstk_darwin — required by blst and pqcrypto on iOS
// Stack probing is handled by the iOS runtime itself
#if defined(__aarch64__)
void __chkstk_darwin(void) {}
#endif
