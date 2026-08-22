/**
 * Minimal DOM helpers. No framework: the page is a handful of panels that
 * re-render from plain data, and a virtual DOM would put a layer between the
 * reader and the thing being taught.
 */

type Attrs = Record<string, string | number | boolean | undefined>

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: (Node | string | null | undefined)[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag)
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === false) continue
    if (k === 'class') node.className = String(v)
    else if (k === 'text') node.textContent = String(v)
    else if (v === true) node.setAttribute(k, '')
    else node.setAttribute(k, String(v))
  }
  for (const c of children) {
    if (c === null || c === undefined) continue
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c)
  }
  return node
}

export function clear(node: Element): void {
  while (node.firstChild) node.removeChild(node.firstChild)
}

export function replace(node: Element, ...children: (Node | string)[]): void {
  clear(node)
  for (const c of children) node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c)
}

/** A paragraph whose text may contain <code> spans, written as `backticks`. */
export function para(text: string, cls?: string): HTMLParagraphElement {
  const p = el('p', cls ? { class: cls } : {})
  appendRich(p, text)
  return p
}

/**
 * Split on backticks and emit <code> for the odd segments. Text is inserted as
 * text nodes throughout, so nothing here can inject markup.
 */
export function appendRich(node: Element, text: string): void {
  const parts = text.split('`')
  parts.forEach((part, i) => {
    if (i % 2 === 1) node.appendChild(el('code', { text: part }))
    else if (part) node.appendChild(document.createTextNode(part))
  })
}

/**
 * A horizontally scrollable region. Keyboard users must be able to reach the
 * scroll container, and a screen reader needs to know it is one - a bare
 * `overflow:auto` div fails on the Linux CI runner even where it passes in a
 * local Chromium.
 */
export function scrollRegion(label: string, ...children: Node[]): HTMLDivElement {
  return el(
    'div',
    { class: 'scroll-x', tabindex: '0', role: 'region', 'aria-label': label },
    children,
  ) as HTMLDivElement
}

export function card(...children: (Node | string)[]): HTMLElement {
  return el('section', { class: 'card' }, children)
}

export function panel(title: string | null, ...children: (Node | string)[]): HTMLElement {
  const p = el('div', { class: 'panel' })
  if (title) p.appendChild(el('p', { class: 'panel-title', text: title }))
  for (const c of children) p.appendChild(typeof c === 'string' ? document.createTextNode(c) : c)
  return p
}

/** A progressive-disclosure panel: the depth an expert wants, shut by default. */
export function deep(summary: string, ...children: Node[]): HTMLDetailsElement {
  const d = el('details', { class: 'deep' }) as HTMLDetailsElement
  d.appendChild(el('summary', { text: summary }))
  for (const c of children) d.appendChild(c)
  return d
}

export function button(
  label: string,
  onClick: () => void,
  opts: { class?: string; id?: string; disabled?: boolean } = {},
): HTMLButtonElement {
  const b = el('button', {
    type: 'button',
    class: opts.class,
    id: opts.id,
    disabled: opts.disabled,
  }) as HTMLButtonElement
  b.textContent = label
  b.addEventListener('click', onClick)
  return b
}

export function labelledInput(
  id: string,
  labelText: string,
  attrs: Attrs,
  onInput: (value: string) => void,
): { wrap: HTMLDivElement; input: HTMLInputElement } {
  const input = el('input', { id, ...attrs }) as HTMLInputElement
  input.addEventListener('input', () => onInput(input.value))
  const wrap = el('div', { class: 'field' }, [el('label', { for: id, text: labelText }), input]) as HTMLDivElement
  return { wrap, input }
}

export function checkbox(
  id: string,
  labelText: string,
  checked: boolean,
  onChange: (checked: boolean) => void,
): { wrap: HTMLDivElement; input: HTMLInputElement } {
  const input = el('input', { type: 'checkbox', id, checked }) as HTMLInputElement
  input.checked = checked
  input.addEventListener('change', () => onChange(input.checked))
  const wrap = el('div', { class: 'switch-row' }, [input, el('label', { for: id, text: labelText })]) as HTMLDivElement
  return { wrap, input }
}

export interface TableSpec {
  readonly caption?: string
  readonly head: readonly string[]
  readonly rows: readonly {
    readonly cells: readonly (string | Node)[]
    readonly rowClass?: string
    readonly cellClasses?: readonly (string | undefined)[]
  }[]
}

export function table(spec: TableSpec): HTMLTableElement {
  const t = el('table') as HTMLTableElement
  if (spec.caption) t.appendChild(el('caption', { text: spec.caption }))
  const thead = el('thead')
  const hr = el('tr')
  spec.head.forEach((h) => hr.appendChild(el('th', { scope: 'col', text: h })))
  thead.appendChild(hr)
  t.appendChild(thead)
  const tbody = el('tbody')
  for (const row of spec.rows) {
    const tr = el('tr', row.rowClass ? { class: row.rowClass } : {})
    row.cells.forEach((c, i) => {
      const cls = row.cellClasses?.[i]
      const td = el(i === 0 ? 'th' : 'td', {
        class: cls,
        ...(i === 0 ? { scope: 'row' } : {}),
      })
      if (typeof c === 'string') td.textContent = c
      else td.appendChild(c)
      tr.appendChild(td)
    })
    tbody.appendChild(tr)
  }
  t.appendChild(tbody)
  return t
}
