<script setup>
import { ref, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  GetModList, ToggleMod, ImportMod, DeleteMod,
  GetInstalledVersions
} from '../../wailsjs/go/main/App.js'
import { showQGLDialog } from '../composables/qglDialog.js'

const emit = defineEmits(['navigate'])

const { t } = useI18n()

function cleanError(e) {
  return String(e).replace('Error: ', '')
}

const selectedVersion = ref('')
const modList = ref([])
const loading = ref(false)
const error = ref('')
const installedVersions = ref([])

onMounted(async () => {
  await loadInstalledVersions()
})

async function loadInstalledVersions() {
  try {
    const versions = await GetInstalledVersions()
    installedVersions.value = versions || []
    if (installedVersions.value.length > 0 && !selectedVersion.value) {
      selectedVersion.value = installedVersions.value[0].folderName
    }
  } catch (e) {
    console.error('加载已安装版本列表失败:', e)
  }
}

async function loadModList() {
  if (!selectedVersion.value) return
  loading.value = true
  error.value = ''
  try {
    const mods = await GetModList(selectedVersion.value)
    modList.value = mods || []
  } catch (e) {
    error.value = cleanError(e)
    modList.value = []
  } finally {
    loading.value = false
  }
}

watch(() => selectedVersion.value, () => { loadModList() })

async function handleToggle(mod) {
  try {
    await ToggleMod(mod.filePath, !mod.isEnabled)
    await loadModList()
  } catch (e) {
    error.value = cleanError(e)
  }
}

async function handleImport() {
  try {
    await ImportMod(selectedVersion.value)
    await loadModList()
  } catch (e) {
    error.value = cleanError(e)
  }
}

async function handleDelete(mod) {
  const btnIndex = await showQGLDialog({
    theme: 'error',
    title: t('mod.delete'),
    content: t('mod.confirmDelete', { name: mod.fileName }),
    btn1Label: t('app.cancel'),
    btn2Label: t('mod.delete')
  })
  if (btnIndex !== 2) return
  try {
    await DeleteMod(mod.filePath)
    await loadModList()
  } catch (e) {
    error.value = cleanError(e)
  }
}

function formatSize(bytes) {
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB'
  if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB'
  return bytes + ' B'
}

const enabledCount = computed(() => modList.value.filter(m => m.isEnabled).length)
const disabledCount = computed(() => modList.value.filter(m => !m.isEnabled).length)
</script>

<template>
  <div class="mod-page">
    <!-- 顶部导航栏 -->
    <div class="top-bar">
      <button class="btn btn-outline" @click="emit('navigate', 'main')">
        &#x2190; {{ t('mod.backToMain') }}
      </button>
      <h2 class="page-title">{{ t('mod.title') }}</h2>
    </div>

    <div class="content-area">
      <!-- 上方控制区玻璃容器 -->
      <div class="mod-top-glass">
      <!-- 版本选择 -->
      <div class="version-selector">
        <label>{{ t('mod.selectGameVersion') }}</label>
        <select v-model="selectedVersion" class="input">
          <option value="" disabled>{{ t('mod.selectVersion') }}</option>
          <option v-for="v in installedVersions" :key="v.folderName" :value="v.folderName">
            <template v-if="v.name">{{ v.name }} - </template>{{ v.version }}<template v-if="v.loader"> ({{ v.loader }})</template>
          </option>
        </select>

        <button class="btn btn-primary" @click="handleImport" :disabled="!selectedVersion">
          {{ t('mod.importMod') }}
        </button>

        <button class="btn btn-outline" @click="loadModList" :disabled="!selectedVersion">
          {{ t('mod.refresh') }}
        </button>
      </div>

      <div v-if="error" class="error-msg">{{ error }}</div>

      <!-- 统计信息 -->
      <div v-if="modList.length > 0" class="mod-stats">
        <span class="stat-item">
          <span class="stat-dot enabled"></span>
          {{ t('mod.enabled') }}: {{ enabledCount }}
        </span>
        <span class="stat-item">
          <span class="stat-dot disabled"></span>
          {{ t('mod.disabled') }}: {{ disabledCount }}
        </span>
        <span class="stat-item">{{ t('mod.total') }}: {{ modList.length }}</span>
      </div>

      </div>
      <!-- 下方MOD列表玻璃容器 -->
      <div class="mod-list-glass">
      <!-- 加载中 -->
      <div v-if="loading" class="loading-area">
        <div class="spin" style="font-size: 32px;">&#x2697;</div>
        <p>{{ t('mod.loadingModList') }}</p>
      </div>

      <!-- MOD 列表 -->
      <div v-else-if="modList.length > 0" class="mod-list">
        <div
          v-for="mod in modList"
          :key="mod.fileName"
          class="mod-item"
          :class="{ disabled: !mod.isEnabled }"
        >
          <div class="mod-item-left">
            <div class="mod-item-icon" :class="{ 'mod-enabled': mod.isEnabled, 'mod-disabled': !mod.isEnabled }">
              {{ mod.fileName[0]?.toUpperCase() || '?' }}
            </div>
            <div class="mod-item-info">
              <div class="mod-item-name">{{ mod.fileName }}</div>
              <div class="mod-item-meta">
                <span class="mod-size">{{ formatSize(mod.fileSize) }}</span>
                <span class="mod-status" :class="mod.isEnabled ? 'enabled' : 'disabled'">
                  {{ mod.isEnabled ? t('mod.enabled') : t('mod.disabled') }}
                </span>
              </div>
            </div>
          </div>
          <div class="mod-item-actions">
            <button
              class="btn btn-sm"
              :class="mod.isEnabled ? 'btn-outline' : 'btn-primary'"
              @click="handleToggle(mod)"
            >
              {{ mod.isEnabled ? t('mod.disable') : t('mod.enable') }}
            </button>
            <button class="btn btn-danger btn-sm" @click="handleDelete(mod)">{{ t('mod.delete') }}</button>
          </div>
        </div>
      </div>

      <!-- 空状态 -->
      <div v-else-if="selectedVersion" class="empty-area">
        <div class="empty-icon">&#x1F4E6;</div>
        <p>{{ t('mod.noModInVersion') }}</p>
        <p class="empty-hint">{{ t('mod.importModHint') }}</p>
        <button class="btn btn-primary" @click="emit('navigate', 'download')">{{ t('mod.goToDownloadMod') }}</button>
      </div>

      <div v-else class="empty-area">
        <div class="empty-icon">&#x1F3AE;</div>
        <p>{{ t('mod.selectVersionFirst') }}</p>
        <p class="empty-hint">{{ t('mod.needDownloadVersion') }}</p>
      </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.mod-page {
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
  padding: 20px;
}

.mod-top-glass {
  padding: 20px 24px;
  border-radius: 14px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(18px);
  -webkit-backdrop-filter: blur(18px);
  border: 1px solid var(--glass-border);
  margin-bottom: 20px;
  transition: background 0.3s;
}

.mod-list-glass {
  flex: 1;
  padding: 20px 24px;
  border-radius: 14px;
  background: var(--glass-bg);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: 1px solid var(--glass-border);
  overflow-y: auto;
  transition: background 0.3s;
}

.version-selector {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.version-selector label {
  font-size: 14px;
  font-weight: 500;
  color: var(--text);
}

.version-selector .input {
  min-width: 200px;
  background: var(--glass-bg-heavy);
}

.error-msg {
  background: var(--glass-bg-heavy);
  color: var(--danger);
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
  margin-bottom: 16px;
  border: 1px solid color-mix(in srgb, var(--danger) 30%, transparent);
}

.mod-stats {
  display: flex;
  gap: 20px;
  margin-bottom: 16px;
  padding: 10px 16px;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 8px;
}

.stat-item {
  font-size: 13px;
  color: var(--text-secondary);
  display: flex;
  align-items: center;
  gap: 6px;
}

.stat-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.stat-dot.enabled { background: var(--success); }
.stat-dot.disabled { background: var(--text-light); }

.loading-area {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 0;
  color: var(--text-secondary);
  gap: 12px;
  background: var(--glass-bg-light);
  border-radius: 10px;
  margin: 20px 0;
}

.spin {
  animation: spin 1s linear infinite;
  display: inline-block;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.mod-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.mod-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 18px;
  border: 1.5px solid var(--border);
  border-radius: 10px;
  transition: all 0.15s;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}

.mod-item:hover {
  border-color: var(--primary);
  box-shadow: 0 2px 8px color-mix(in srgb, var(--primary) 10%, transparent);
}

.mod-item.disabled { opacity: 0.65; }

.mod-item-left {
  display: flex;
  align-items: center;
  gap: 14px;
  flex: 1;
  min-width: 0;
}

.mod-item-icon {
  width: 40px;
  height: 40px;
  border-radius: 10px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  font-weight: 700;
  color: white;
  flex-shrink: 0;
}

.mod-item-icon.mod-enabled { background: var(--primary); }
.mod-item-icon.mod-disabled { background: var(--text-light); }

.mod-item-info {
  flex: 1;
  min-width: 0;
}

.mod-item-name {
  font-size: 14px;
  font-weight: 500;
  color: var(--text);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.mod-item-meta {
  display: flex;
  gap: 10px;
  margin-top: 4px;
}

.mod-size { font-size: 12px; color: var(--text-light); }
.mod-status { font-size: 12px; font-weight: 500; }
.mod-status.enabled { color: var(--success); }
.mod-status.disabled { color: var(--text-light); }

.mod-item-actions {
  display: flex;
  gap: 6px;
  flex-shrink: 0;
  margin-left: 12px;
}

.btn-danger {
  background: var(--danger);
  border-color: var(--danger);
  color: white;
}

.btn-danger:hover {
  background: color-mix(in srgb, var(--danger) 80%, black);
}

.empty-area {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 48px 0;
  gap: 12px;
  color: var(--text-secondary);
  background: var(--glass-bg-light);
  border-radius: 10px;
  margin: 20px 0;
  border: 1px dashed var(--border);
}

.empty-icon { font-size: 48px; }
.empty-hint { font-size: 13px; color: var(--text-light); }
</style>
