export function LoadingState({ label = "Loading telemetry..." }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 py-24">
      <div className="relative h-10 w-10">
        <div className="absolute inset-0 rounded-full border-2 border-brand/20" />
        <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-brand animate-spin shadow-glow-brand" />
      </div>
      <span className="text-xs font-medium uppercase tracking-widest text-slate-400">{label}</span>
    </div>
  );
}
