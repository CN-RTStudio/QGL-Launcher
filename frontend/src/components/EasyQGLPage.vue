<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { useEasyQGL } from '../stores/easyQGL.js'
import {
  AddToDownloadListWithLoader, AddModToDownloadList, StartDownloadList,
  GetVersionManifest, GetDefaultModDir, GetForgeVersions, GetFabricVersions, GetNeoForgeVersions,
  GetDownloadList, GetInstalledVersions, ResolveModDependencies
} from '../../wailsjs/go/main/App.js'
import { EventsOn, EventsOff } from '../../wailsjs/runtime/runtime.js'

const { t } = useI18n()
const emit = defineEmits(['navigate'])

const { state: easyQGL, enterModFirstMode, exitMode } = useEasyQGL()

function cleanError(e) {
  return String(e).replace('Error: ', '')
}

function parseVersionNum(ver) {
  return ver.split('.').map(n => parseInt(n, 10) || 0)
}

function compareVersionNum(a, b) {
  const pa = parseVersionNum(a)
  const pb = parseVersionNum(b)
  const len = Math.max(pa.length, pb.length)
  for (let i = 0; i < len; i++) {
    const na = pa[i] || 0
    const nb = pb[i] || 0
    if (na !== nb) return na - nb
  }
  return 0
}

// 安装状态
const installStep = ref(0) // 0=未开始, 1=安装游戏, 2=下载mod, 3=添加mod, 4=完成
const installMsg = ref('')
const installError = ref('')
const installLog = ref([]) // 安装日志

const stepLabelsI18n = computed(() => [
  t('easyQGL.step1InstallGame'),
  t('easyQGL.step2DownloadMods'),
  t('easyQGL.step3AddMods'),
  t('easyQGL.step4Complete'),
])

const modeLabel = computed(() => {
  if (!easyQGL.active) return ''
  if (easyQGL.mode === 'mod-first') return t('easyQGL.modFirstMode')
  if (easyQGL.mode === 'version-first') return t('easyQGL.versionFirstMode')
  return ''
})

function addLog(msg) {
  installLog.value.push(msg)
}

function handleModFirst() {
  enterModFirstMode()
  emit('navigate', 'download')
}

function handleVersionFirst() {
  // 暂未实现
}

function handleExitMode() {
  exitMode()
}

function getLoaderVersions(loaderName, gameVersion) {
  switch (loaderName) {
    case 'forge': return GetForgeVersions(gameVersion)
    case 'fabric': return GetFabricVersions(gameVersion)
    case 'neoforge': return GetNeoForgeVersions(gameVersion)
    default: return Promise.resolve([])
  }
}

async function handleInstall() {
  if (easyQGL.selectedMods.length === 0 || installStep.value > 0) return
  if (!easyQGL.lockedGameVersion || !easyQGL.lockedLoader) {
    installError.value = t('easyQGL.missingVersionOrLoader')
    return
  }

  installError.value = ''
  installLog.value = []

  try {
    // ===== 步骤1：安装游戏和加载器 =====
    installStep.value = 1
    installMsg.value = t('easyQGL.preparingInstall')
    addLog(t('easyQGL.startInstallGame'))

    const versions = await GetVersionManifest()
    const targetVer = versions.find(v => v.id === easyQGL.lockedGameVersion)
    if (!targetVer) {
      throw new Error(t('easyQGL.versionNotFound', { version: easyQGL.lockedGameVersion }))
    }

    installMsg.value = t('easyQGL.queryingLoader')
    const loaderName = easyQGL.lockedLoader
    const loaderVersions = await getLoaderVersions(loaderName, easyQGL.lockedGameVersion)
    if (!loaderVersions || loaderVersions.length === 0) {
      throw new Error(t('easyQGL.loaderNotFound', { loader: loaderName }))
    }

    let loaderVer = loaderVersions[0]
    for (const v of loaderVersions) {
      if (compareVersionNum(v.version || '', loaderVer.version || '') > 0) {
        loaderVer = v
      }
    }

    const loaderVersionStr = loaderVer.forgeVersion || loaderVer.version || loaderVer.name || ''
    const loaderDisplayVer = loaderVer.version || ''
    const customName = easyQGL.lockedGameVersion + '-' + loaderName + '-' + loaderVersionStr

    addLog(`${t('easyQGL.gameVersion')}${easyQGL.lockedGameVersion}`)
    addLog(`${t('easyQGL.loader')}${loaderName} ${loaderDisplayVer}${t('easyQGL.highestVersion')}`)
    addLog(t('easyQGL.availableVersionCount', { count: loaderVersions.length }))
    addLog(t('easyQGL.versionName', { name: customName }))

    const versionsBefore = await GetInstalledVersions()
    const beforeFolderNames = versionsBefore.map(v => v.folderName)
    addLog(t('easyQGL.versionsBeforeCount', { count: versionsBefore.length }))

    installMsg.value = t('easyQGL.downloadingGame')
    addLog(t('easyQGL.addingToDownloadList'))
    await AddToDownloadListWithLoader(
      targetVer.id,
      targetVer.url,
      customName,
      targetVer.type || 'release',
      loaderName,
      loaderVersionStr,
      '',
      ''
    )

    addLog(t('easyQGL.startDownloading'))
    const gameDownloadPromise = waitForDownloadComplete()
    await StartDownloadList()
    await gameDownloadPromise

    const listAfterGame = await GetDownloadList()
    const gameItem = listAfterGame.find(item =>
      item.customName && item.customName.includes(customName) && item.itemType === 'game+loader'
    )
    if (gameItem && gameItem.Status === 'failed') {
      throw new Error(t('easyQGL.installFailed') + (gameItem.ErrorMsg || t('easyQGL.unknownError')))
    }

    addLog(t('easyQGL.installDone'))

    const versionsAfter = await GetInstalledVersions()
    const newVersions = versionsAfter.filter(v => !beforeFolderNames.includes(v.folderName))
    const newVersionNames = newVersions.map(v => v.folderName)
    addLog(t('easyQGL.newVersions', { versions: newVersionNames.join(', ') }))

    let installedVersionName = customName
    const loaderNameLower = loaderName.toLowerCase()
    for (const v of newVersions) {
      if (v.folderName.toLowerCase().includes(loaderNameLower)) {
        installedVersionName = v.folderName
        break
      }
    }
    addLog(t('easyQGL.actualInstalledVersion', { version: installedVersionName }))

    // ===== 步骤2：下载模组 =====
    installStep.value = 2
    installMsg.value = t('easyQGL.resolvingDeps')
    addLog(t('easyQGL.startDownloadingMods'))

    const modDir = await GetDefaultModDir(installedVersionName)
    addLog(t('easyQGL.modDirLog', { dir: modDir }))

    // 同时保留 mod 引用，避免 selectedMods 与 versionIDs 过滤后索引错位
    const selectedPairs = easyQGL.selectedMods
      .filter(m => m.versionId)
      .map(m => ({ versionId: m.versionId, mod: m }))

    let allMods = [...selectedPairs]

    if (selectedPairs.length > 0) {
      addLog(t('easyQGL.resolvingDeps'))
      try {
        const versionIDs = selectedPairs.map(p => p.versionId)
        const deps = await ResolveModDependencies(versionIDs, easyQGL.lockedGameVersion, easyQGL.lockedLoader)
        if (deps && deps.length > 0) {
          addLog(t('easyQGL.foundDeps', { count: deps.length }))
          for (const dep of deps) {
            addLog(`  - ${dep.projectName} (${dep.dependencyType})`)
            allMods.push({ versionId: dep.versionId, mod: null, dep })
          }
        } else {
          addLog(t('easyQGL.noExtraDeps'))
        }
      } catch (e) {
        addLog(t('easyQGL.resolvingDepsFailed') + cleanError(e))
      }
    }

    const totalMods = allMods.length
    for (let i = 0; i < totalMods; i++) {
      const { versionId, mod, dep } = allMods[i]
      const isDep = !mod
      installMsg.value = t('easyQGL.addingMod', { current: i + 1, total: totalMods })
      if (isDep) addLog(t('easyQGL.addingDepMod') + dep.projectName)
      else addLog(t('easyQGL.addingModLog', { name: mod.title || mod.slug }))
      await AddModToDownloadList(versionId, modDir)
    }

    installMsg.value = t('easyQGL.downloadingMods')
    addLog(t('easyQGL.startDownloadingMods'))
    const modDownloadPromise = waitForDownloadComplete()
    await StartDownloadList()
    await modDownloadPromise

    addLog(t('easyQGL.modsDownloadDone'))

    // ===== 步骤3：添加mod =====
    installStep.value = 3
    installMsg.value = t('easyQGL.addingMods')
    addLog(t('easyQGL.modsAddedAuto'))

    await new Promise(resolve => setTimeout(resolve, 800))

    // ===== 步骤4：完成 =====
    installStep.value = 4
    installMsg.value = t('easyQGL.installComplete')
    addLog(t('easyQGL.allInstallDone'))

  } catch (e) {
    installError.value = t('easyQGL.error') + cleanError(e)
    addLog(t('easyQGL.error') + installError.value)
  }
}

let downloadCompleteResolve = null

function waitForDownloadComplete() {
  return new Promise((resolve) => {
    downloadCompleteResolve = resolve
  })
}

function onDownloadCompleted() {
  if (downloadCompleteResolve) {
    const resolve = downloadCompleteResolve
    downloadCompleteResolve = null
    resolve()
  }
}

onMounted(() => {
  EventsOn('downloadListCompleted', onDownloadCompleted)
})

onUnmounted(() => {
  EventsOff('downloadListCompleted')
  if (downloadCompleteResolve) {
    downloadCompleteResolve = null
  }
})

function goBack() {
  if (installStep.value > 0 && installStep.value < 4) return
  emit('navigate', 'main')
}

function handleReturnToNormal() {
  exitMode()
  emit('navigate', 'main')
}
</script>

<template>
  <div class="easyqgl-page">
    <!-- 顶部导航栏 -->
    <div class="top-bar">
      <button class="btn btn-outline" @click="goBack" :disabled="installStep > 0 && installStep < 4">
        {{ $t('easyQGL.backToMain') }}
      </button>
      <h2 class="page-title">{{ $t('easyQGL.title') }}</h2>
    </div>

    <div class="content-area">
      <!-- 未进入模式：显示两个选项 -->
      <div v-if="!easyQGL.active" class="choice-section">
        <div class="glass-container choice-header">
          <div class="choice-icon">✨</div>
          <h2>{{ $t('easyQGL.easyInstallMod') }}</h2>
          <p class="choice-desc">{{ $t('easyQGL.easyInstallDesc') }}</p>
        </div>

        <div class="choice-cards">
          <div class="glass-container choice-card" @click="handleModFirst">
            <div class="choice-card-icon">🔍</div>
            <div class="choice-card-title">{{ $t('easyQGL.modFirst') }}</div>
            <div class="choice-card-desc">{{ $t('easyQGL.modFirstDesc') }}</div>
          </div>

          <div class="glass-container choice-card disabled-card">
            <div class="choice-card-icon">🎮</div>
            <div class="choice-card-title">{{ $t('easyQGL.versionFirst') }}</div>
            <div class="choice-card-desc">{{ $t('easyQGL.versionFirstDesc') }}</div>
            <div class="coming-soon-badge">{{ $t('easyQGL.comingSoon') }}</div>
          </div>
        </div>
      </div>

      <!-- 已进入模式：显示当前模式和操作 -->
      <div v-else class="mode-section">
        <div class="glass-container mode-header">
          <div class="mode-badge">{{ modeLabel }}</div>
          <div class="mode-info">
            <div v-if="easyQGL.lockedGameVersion" class="mode-detail">
              {{ $t('easyQGL.gameVersion') }}<strong>{{ easyQGL.lockedGameVersion }}</strong>
            </div>
            <div v-if="easyQGL.lockedLoader" class="mode-detail">
              {{ $t('easyQGL.loader') }}<strong>{{ easyQGL.lockedLoader }}</strong>
            </div>
            <div class="mode-detail">
              {{ $t('easyQGL.selectedMods') }}<strong>{{ $t('easyQGL.selectedModsCount', { count: easyQGL.selectedMods.length }) }}</strong>
            </div>
          </div>
        </div>

        <!-- 安装流程图 -->
        <div v-if="installStep > 0" class="glass-container flow-chart">
          <div class="flow-steps">
            <template v-for="(label, idx) in stepLabelsI18n" :key="idx">
              <div
                class="flow-step"
                :class="{
                  active: installStep === idx + 1,
                  done: installStep > idx + 1,
                  pending: installStep < idx + 1
                }"
              >
                <div class="flow-dot">
                  <span v-if="installStep > idx + 1">✓</span>
                  <span v-else>{{ idx + 1 }}</span>
                </div>
                <div class="flow-label">{{ label }}</div>
              </div>
              <div v-if="idx < stepLabelsI18n.length - 1" class="flow-line" :class="{ done: installStep > idx + 1 }"></div>
            </template>
          </div>

          <div class="flow-message">{{ installMsg }}</div>

          <!-- 安装日志 -->
          <div v-if="installLog.length > 0" class="flow-log">
            <div v-for="(log, idx) in installLog" :key="idx" class="log-line">{{ log }}</div>
          </div>

          <div v-if="installError" class="flow-error">{{ installError }}</div>
        </div>

        <div class="glass-container mode-actions">
          <button
            v-if="installStep === 0 || installStep === 4"
            class="btn btn-outline"
            @click="installStep === 4 ? handleReturnToNormal() : handleExitMode()"
          >
            {{ installStep === 4 ? $t('easyQGL.returnToNormal') : $t('easyQGL.exitMode') }}
          </button>
          <button
            v-if="installStep === 0"
            class="btn btn-primary install-btn"
            :disabled="easyQGL.selectedMods.length === 0"
            @click="handleInstall"
          >
            {{ $t('easyQGL.install') }}
          </button>
        </div>

        <!-- 已选模组列表 -->
        <div v-if="easyQGL.selectedMods.length > 0 && installStep === 0" class="glass-container selected-mods">
          <h3>{{ $t('easyQGL.selectedModsTitle') }}</h3>
          <div class="mod-list">
            <div v-for="(mod, idx) in easyQGL.selectedMods" :key="idx" class="mod-item">
              <div class="mod-icon">{{ mod.title?.charAt(0) || '?' }}</div>
              <div class="mod-info">
                <div class="mod-name">{{ mod.title || mod.slug }}</div>
                <div class="mod-desc">{{ mod.description || '' }}</div>
              </div>
            </div>
          </div>
        </div>

        <div v-if="easyQGL.selectedMods.length === 0 && installStep === 0" class="glass-container empty-mods">
          <div class="empty-icon">📦</div>
          <p>{{ $t('easyQGL.noModsSelected') }}</p>
          <p class="empty-hint">{{ $t('easyQGL.noModsHint') }}</p>
          <button class="btn btn-primary" @click="emit('navigate', 'download')">
            {{ $t('easyQGL.browseMods') }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.easyqgl-page {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  background: transparent;
  position: relative;
  z-index: 2;
}

.top-bar {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px 24px;
  border-bottom: 1px solid var(--border);
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
}

.page-title {
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
}

.content-area {
  flex: 1;
  overflow-y: auto;
  padding: 32px 40px;
}

.glass-container {
  background: var(--glass-bg);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 14px;
}

.choice-section {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding-top: 40px;
}

.choice-header {
  text-align: center;
  margin-bottom: 40px;
  padding: 32px 48px;
}

.choice-icon { font-size: 56px; margin-bottom: 16px; }
.choice-header h2 { font-size: 28px; font-weight: 700; color: var(--text); margin-bottom: 8px; }
.choice-desc { font-size: 15px; color: var(--text-secondary); }

.choice-cards { display: flex; gap: 24px; justify-content: center; }

.choice-card {
  width: 280px; padding: 32px 24px; cursor: pointer;
  transition: all 0.2s; text-align: center; position: relative;
}
.choice-card:hover:not(.disabled-card) {
  border-color: var(--primary);
  box-shadow: 0 6px 24px color-mix(in srgb, var(--primary) 15%, transparent);
  transform: translateY(-2px);
}
.disabled-card { opacity: 0.5; cursor: not-allowed; }
.choice-card-icon { font-size: 48px; margin-bottom: 16px; }
.choice-card-title { font-size: 20px; font-weight: 700; color: var(--text); margin-bottom: 8px; }
.choice-card-desc { font-size: 13px; color: var(--text-secondary); line-height: 1.5; }
.coming-soon-badge {
  position: absolute; top: 12px; right: 12px; padding: 2px 10px;
  background: var(--primary); color: white; border-radius: 10px; font-size: 11px; font-weight: 600;
}

.mode-section { max-width: 650px; margin: 0 auto; }

.mode-header {
  padding: 20px 24px;
  border-color: color-mix(in srgb, var(--primary) 25%, transparent);
  margin-bottom: 16px;
}
.mode-badge {
  display: inline-block; padding: 4px 12px; background: var(--primary); color: white;
  border-radius: 6px; font-size: 13px; font-weight: 600; margin-bottom: 12px;
}
.mode-info { display: flex; flex-direction: column; gap: 6px; }
.mode-detail { font-size: 14px; color: var(--text-secondary); }
.mode-detail strong { color: var(--text); }

/* 流程图 */
.flow-chart {
  padding: 24px; margin-bottom: 16px;
  border-color: color-mix(in srgb, var(--primary) 25%, transparent);
}

.flow-steps {
  display: flex; align-items: flex-start; justify-content: center; gap: 0; margin-bottom: 20px;
}

.flow-step {
  display: flex; flex-direction: column; align-items: center; gap: 8px; min-width: 80px;
}

.flow-dot {
  width: 36px; height: 36px; border-radius: 50%; display: flex; align-items: center;
  justify-content: center; font-size: 14px; font-weight: 700; flex-shrink: 0;
  background: var(--border); color: var(--text-secondary); transition: all 0.3s;
}

.flow-step.active .flow-dot {
  background: var(--primary); color: white;
  box-shadow: 0 0 12px color-mix(in srgb, var(--primary) 40%, transparent);
}
.flow-step.done .flow-dot { background: var(--success); color: white; }
.flow-step.pending .flow-dot { background: var(--border); color: var(--text-light); }

.flow-label {
  font-size: 12px; color: var(--text-secondary); text-align: center; white-space: nowrap;
}
.flow-step.active .flow-label { color: var(--primary); font-weight: 600; }
.flow-step.done .flow-label { color: var(--success); }

.flow-line {
  flex: 1; height: 3px; background: var(--border); margin-top: 17px; min-width: 32px;
  transition: background 0.3s;
}
.flow-line.done { background: var(--success); }

.flow-message {
  font-size: 15px; color: var(--text); font-weight: 500; text-align: center; margin-bottom: 12px;
}

.flow-log {
  background: var(--glass-bg-light);
  border-radius: 8px; padding: 12px; max-height: 150px;
  overflow-y: auto; margin-bottom: 8px;
}
.log-line {
  font-size: 12px; color: var(--text-secondary); line-height: 1.6; font-family: monospace;
}

.flow-error {
  font-size: 13px; color: var(--danger); text-align: center; margin-top: 8px;
}

.mode-actions {
  display: flex; gap: 12px; padding: 16px 20px; margin-bottom: 16px;
}

.install-btn { background: var(--primary); border-color: var(--primary); }
.install-btn:hover:not(:disabled) { background: var(--primary-dark); }
.install-btn:disabled { opacity: 0.5; cursor: not-allowed; }

.selected-mods { padding: 20px 24px; }
.selected-mods h3 { font-size: 15px; font-weight: 600; color: var(--text); margin-bottom: 12px; }
.mod-list { display: flex; flex-direction: column; gap: 8px; }

.mod-item {
  display: flex; align-items: center; gap: 12px; padding: 10px 14px;
  background: color-mix(in srgb, var(--primary) 6%, var(--glass-bg-light));
  border: 1px solid color-mix(in srgb, var(--primary) 15%, transparent);
  border-radius: 10px;
}
.mod-icon {
  width: 36px; height: 36px; border-radius: 8px; background: var(--primary); color: white;
  display: flex; align-items: center; justify-content: center; font-size: 16px;
  font-weight: 700; flex-shrink: 0;
}
.mod-info { flex: 1; min-width: 0; }
.mod-name { font-size: 14px; font-weight: 500; color: var(--text); }
.mod-desc { font-size: 12px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

.empty-mods {
  display: flex; flex-direction: column; align-items: center; padding: 48px 24px; gap: 12px;
  color: var(--text-secondary);
}
.empty-icon { font-size: 48px; }
.empty-hint { font-size: 13px; color: var(--text-light); }
</style>
