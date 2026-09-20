package provider

// unregister removes a detector registered by a test.
//
// The registry is package-level state and Register is append-only by design --
// backends register from init and never leave. Tests that register a fake must
// remove it again, or a later test sees a provider that does not exist and the
// suite stops being order-independent.
func unregister(name string) {
	mu.Lock()
	defer mu.Unlock()
	kept := detectors[:0]
	for _, d := range detectors {
		if d.Name() != name {
			kept = append(kept, d)
		}
	}
	detectors = kept
}
