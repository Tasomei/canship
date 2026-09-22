/** 仅在 GitHub 验收任务中读取分析结果，不输出令牌或报告详情。 */
const { GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_SHA } = process.env
if (!GITHUB_TOKEN || !GITHUB_REPOSITORY || !GITHUB_SHA) throw new Error('Missing GitHub workflow context.')
const fixturePath = 'test/fixtures/evaluation/firebase-quickstart/firestore.rules'

async function read(endpoint) {
  const response = await fetch(`https://api.github.com/repos/${GITHUB_REPOSITORY}/code-scanning/${endpoint}`, {
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
    signal: AbortSignal.timeout(15_000),
  })
  if (!response.ok) throw new Error(`GitHub code scanning request failed (${response.status}).`)
  return response.json()
}

let verified = false
for (let attempt = 0; attempt < 6; attempt++) {
  const analyses = await read('analyses?tool_name=canship&per_page=100')
  const analysis = analyses.find(item => item.commit_sha === GITHUB_SHA &&
    item.category?.startsWith('canship-fixture-validation') && item.results_count === 2 && !item.error)
  if (analysis) {
    const alerts = await read('alerts?tool_name=canship&per_page=100')
    const matching = alerts.filter(item => item.most_recent_instance?.commit_sha === GITHUB_SHA &&
      item.most_recent_instance?.location?.path === fixturePath &&
      item.rule?.id === 'firebase/open-rules')
    if (matching.length === 2 && matching.every(item => item.most_recent_instance.location.start_line > 0)) {
      console.log('Verified: two intentional public-read fixture findings have repository paths and line numbers.')
      verified = true
      break
    }
  }
  if (attempt < 5) await new Promise(resolve => setTimeout(resolve, 5000))
}
if (!verified) throw new Error('SARIF upload did not produce the expected fixture analysis and locations.')
