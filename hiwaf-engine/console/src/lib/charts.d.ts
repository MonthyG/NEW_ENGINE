// Types for the global installed by charts.js (tasteskill assets/charts.js).
interface ChartsApi {
  line(el: Element, opts: Record<string, unknown>): { legend?: HTMLElement } | void
  bars(el: Element, opts: Record<string, unknown>): void
  barList(el: Element, rows: { label: string; value: number }[], opts?: Record<string, unknown>): void
  ring(el: Element, opts: Record<string, unknown>): void
  fmt: Record<string, any>
}
declare global {
  interface Window { Charts: ChartsApi }
}
export {}
