// Node 22 marks its built-in SQLite module experimental. Keep all other
// warnings visible, including other ExperimentalWarnings.
const originalEmitWarning = process.emitWarning;
const sqliteWarning = "SQLite is an experimental feature and might change at any time";
process.emitWarning = ((...args: unknown[]) => {
  const warning = args[0];
  const options = args[1];
  const type = warning instanceof Error ? warning.name
    : typeof options === "string" ? options
    : typeof options === "object" && options !== null && "type" in options ? options.type
    : undefined;
  const message = warning instanceof Error ? warning.message : warning;
  if (type === "ExperimentalWarning" && message === sqliteWarning) return;
  return Reflect.apply(originalEmitWarning, process, args);
}) as typeof process.emitWarning;
