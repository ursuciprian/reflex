// Stubbed Jev for the router self-checks (REFLEX_ROUTER_STUB): same contract as gate.ask().
//   __category__ / __tool__   the option whose name (after the last ".") appears in the intent, longest
//                             first; "ambiguous" in the intent spreads the probability; no match -> none
//   arg.<k> choice            the value v from "k=v" in the intent; "weak" as the value -> p 0.3
//   arg.<k> noul              0.9 when k appears in the intent, else 0.1
export const calls = [];
const spread = (options, choice, p) => Object.fromEntries(options.map(o => [o, o === choice ? p : (1 - p) / Math.max(1, options.length - 1)]));
export default async function ask(state, questions) {
  calls.push({state, questions});
  const intent = state.request.intent, answers = {};
  for (const [id, q] of Object.entries(questions)) {
    if (q.type === "noul") { answers[id] = {noul: intent.includes(id.slice(4)) ? 0.9 : 0.1}; continue; }
    const options = Object.keys(q.criteria);
    let choice, p = 0.95;
    if (id.startsWith("arg.")) {
      const v = intent.match(new RegExp(`\\b${id.slice(4)}=(\\S+)`))?.[1];
      choice = options.includes(v) ? v : "none_of_these";
      if (v === "weak") p = 0.3;
    } else if (intent.includes("ambiguous")) {
      const [a, b] = options;
      answers[id] = {choice: a, confidence: 0.2,
        probabilities: Object.fromEntries(options.map(o => [o, o === a ? 0.4 : o === b ? 0.35 : 0.25 / (options.length - 2)]))};
      continue;
    } else {
      choice = options.filter(o => intent.includes(o.split(".").at(-1))).sort((x, y) => y.length - x.length)[0] ?? "none_of_these";
    }
    answers[id] = {choice, confidence: p, probabilities: spread(options, choice, p)};
  }
  return {answers, usage: {input_tokens: 0}, error: null, latency_s: 0};
}
