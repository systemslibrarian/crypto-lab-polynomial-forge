import { expect, test } from '@playwright/test'

test('two false individual openings pass only the premature batch check', async ({ page }) => {
  await page.goto('.')
  await expect(page.locator('html')).toHaveAttribute('data-app-ready', 'true')
  await expect(page.locator('#batch-case')).toHaveValue('honest')
  for (const z of ['5', '7']) {
    await page.selectOption('#batch-point', z)
    for (const scenario of ['honest', 'attack']) {
      await page.selectOption('#batch-case', scenario)
      await page.click('#batch-run')
      const attack = scenario === 'attack'
      await expect(page.locator('#batch-early')).toHaveAttribute('data-kind', attack ? 'alarm' : 'ok')
      await expect(page.locator('#batch-early')).toContainText(attack ? 'ACCEPTED — AND FALSE' : 'ACCEPTED — TRUE')
      await expect(page.locator('#batch-bound')).toHaveAttribute('data-kind', attack ? 'rejected' : 'ok')
      const rows = page.locator('#batch-results tbody tr')
      await expect(rows).toHaveCount(2)
      for (let i = 0; i < 2; i++) {
        const cells = await rows.nth(i).locator('th,td').allTextContents()
        const point = Number(cells[0])
        const actual = 3 + 2 * point + point * point
        expect(Number(cells[1])).toBe(actual)
        expect(Number(cells[2])).toBe(actual + (attack ? i + 1 : 0))
        expect(cells[3]).toBe(attack ? 'REJECTED' : 'ACCEPTED')
      }
      await page.locator('#batch-results summary').click()
      const bytes = (await page.locator('#batch-bytes').textContent())!
      const read = (key: string) => bytes.split('\n').find(l => l.startsWith(key + ': '))!.slice(key.length + 2)
      expect(read('Premature u')).not.toBe(read('Proof-bound u'))
      expect(read('W1')).not.toBe(read('W2'))
      expect(read('W1')).toHaveLength(96)
      await expect(page.locator('#batch-act')).toContainText('not a complete PLONK exploit')
      await expect(page.locator('#batch-act')).toContainText('not a security proof for every protocol')
      if (attack) {
        await expect(page.locator('#batch-results')).toContainText('Their errors cancel')
        expect(read('Premature weighted witness')).not.toBe(read('Bound weighted witness'))
      }
    }
  }
})

test('batch results retire for changed controls and ceremony, not a no-op', async ({ page }) => {
  await page.goto('.')
  await expect(page.locator('html')).toHaveAttribute('data-app-ready', 'true')
  await page.click('#batch-run')
  await page.locator('#batch-case').dispatchEvent('change')
  await expect(page.locator('#batch-results')).toBeVisible()
  await page.selectOption('#batch-point', '7')
  await expect(page.locator('#batch-results')).toBeHidden()
  await expect(page.locator('#batch-bound')).toContainText('RETIRED')
  await page.click('#batch-run')
  await page.click('#mode-0-retain')
  await expect(page.locator('#batch-results')).toBeHidden()
  await expect(page.locator('#batch-early')).toContainText('ceremony changed')
  await page.click('#batch-run')
  await expect(page.locator('#batch-bound')).toContainText('ACCEPTED — TRUE')
})
