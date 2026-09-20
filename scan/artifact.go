package scan

import "reflect"

// ArtifactOf is the plan identity of T.
//
// The execution store has always been keyed by Go type while StageDescriptor
// used hand-written strings. That left two contracts for one fact: a producer
// could declare "probe-result" and publish some other type, the plan would
// validate, and its consumer would quietly observe absence. Deriving the plan
// identity from the same type Put and Get use makes that drift impossible.
func ArtifactOf[T any]() ArtifactType {
	return artifactTypeName(typeOf[T]())
}

func typeOf[T any]() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }

func artifactTypeName(t reflect.Type) ArtifactType {
	if t == nil {
		return "<nil>"
	}
	return ArtifactType(t.PkgPath() + "." + t.String())
}

// Artifacts are the typed values stages hand to each other.
//
// They replace the Out pointer. A Supabase stage used to publish its result
// through `Out *probe.Result`, and the variable behind that pointer was
// declared in scanTarget -- so the wiring between two Supabase stages lived in
// main, and reordering them, dropping one or handing one to a contributor
// meant editing the command. That is the thirty-variables-of-shared-scope
// problem this package was created to end, wearing a struct field.
//
// KEYED BY TYPE, NOT BY NAME. A string-keyed bag is a contract two packages
// must agree on out of band, and a typo in either half is silent: the producer
// writes "probe-result", the consumer reads "probe_result", and the consumer
// sees a stage that never ran. The compiler checks a type.
//
// This keeps the pipeline PROVIDER-AGNOSTIC, which was the objection to
// putting probe.Result on State directly and remains a good one. Put and Get
// are generic, so nothing here names a PostgREST type, a Firestore type or any
// other; scan gains no import and no field that only one backend can populate.
// The artifact types stay in the backend package that defines them.

// Put stores v, replacing any earlier value of the same type.
//
// Replacement rather than accumulation: a stage that runs twice in one scan
// replaces its own artifact, because silently appending would make the result
// depend on how many times the pipeline was built.
func Put[T any](st *State, v T) {
	if st.artifacts == nil {
		st.artifacts = map[reflect.Type]any{}
	}
	t := typeOf[T]()
	st.artifacts[t] = v
	st.recordArtifactWrite(artifactTypeName(t))
}

// Get returns the artifact of type T and whether one was ever put.
//
// THE BOOL IS THE POINT. A stage that did not run leaves nothing behind, and a
// consumer must be able to tell that from a stage that ran and found nothing.
// Returning only T makes the two the same empty struct -- which is how "the
// probe stage was skipped" comes to read as "the probe found no relations", in
// a tool whose entire argument is that those are different things.
//
// Callers that genuinely do not care can ignore the bool; callers that steer
// on the artifact must not.
func Get[T any](st *State) (T, bool) {
	var zero T
	if st == nil || st.artifacts == nil {
		return zero, false
	}
	typ := typeOf[T]()
	st.recordArtifactRead(artifactTypeName(typ))
	v, ok := st.artifacts[typ]
	if !ok {
		return zero, false
	}
	got, ok := v.(T)
	return got, ok
}
