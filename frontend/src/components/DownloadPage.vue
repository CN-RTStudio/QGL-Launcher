<script setup>
import { ref, onMounted, watch, computed } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  GetVersionManifest, AddToDownloadList, AddToDownloadListWithLoader, AddJavaToDownloadList,
  GetJavaDownloadList, SearchJava, SearchMods, GetModVersions,
  GetModDependencies, AddModToDownloadList, SelectModSaveDir,
  GetDefaultModDir, GetModrinthCategories,
  GetForgeVersions, GetFabricVersions, GetNeoForgeVersions, GetOptiFineVersions,
  CheckLoaderInstalled,
  GetInstalledVersions, TranslateModName, SearchModsByChineseName,
  SearchModpacks, GetModpackVersions, AddModpackToDownloadList
} from '../../wailsjs/go/main/App.js'
import { useEasyQGL } from '../stores/easyQGL.js'

const props = defineProps({
  currentUser: Object
})

const emit = defineEmits(['navigate'])

const { t } = useI18n()

const { state: easyQGL, setFirstMod, addSelectedMod } = useEasyQGL()

function cleanError(e) {
  return String(e).replace('Error: ', '')
}

function recordEasyQGLMod(versionId, versionInfo) {
  if (!easyQGL.active || !selectedMod.value) return
  if (!easyQGL.firstMod) setFirstMod(selectedMod.value, versionInfo)
  addSelectedMod({
    title: selectedMod.value.title,
    slug: selectedMod.value.slug,
    description: selectedMod.value.description,
    versionId,
    versionName: versionInfo?.name || versionInfo?.version_number || ''
  })
}

const versions = ref([])
const loading = ref(false)
const error = ref('')
const selectedVersion = ref(null)
const customName = ref('')
const filterType = ref('release')
const adding = ref(false)
const addSuccess = ref(false)

const activeTab = ref(easyQGL.active && easyQGL.mode === 'mod-first' ? 'mod' : 'game')

const javaList = ref([])
const installedJavaList = ref([])

const modQuery = ref('')
const modSearchResults = ref([])
const modSearching = ref(false)
const modSearchTotal = ref(0)
const modSearchPage = ref(0)
const modGameVersion = ref(easyQGL.active && easyQGL.lockedGameVersion ? easyQGL.lockedGameVersion : '')
const modLoader = ref(easyQGL.active && easyQGL.lockedLoader ? easyQGL.lockedLoader : '')
const modCategory = ref('')
const modCategories = ref([])
const selectedMod = ref(null)
const modVersions = ref([])
const modVersionsLoading = ref(false)
const modDependencies = ref([])
const modDepsLoading = ref(false)
const modSavePath = ref('')

const showAdvanced = ref(false)
const loaderTab = ref('forge')
const loaderVersions = ref([])
const loaderLoading = ref(false)
const loaderInstalling = ref(false)
const loaderInstalled = ref({})
const installedGameVersions = ref([])
const selectedLoader = ref(null)

const modpackQuery = ref('')
const modpackSearchResults = ref([])
const modpackSearching = ref(false)
const modpackSearchTotal = ref(0)
const modpackSearchPage = ref(0)
const modpackGameVersion = ref('')
const selectedModpack = ref(null)
const modpackVersions = ref([])
const modpackVersionsLoading = ref(false)

onMounted(async () => {
  await loadVersions()
  await loadJavaList()
  await loadModCategories()
  await loadInstalledVersions()
})

watch(() => easyQGL.active, () => {
  if (easyQGL.active && easyQGL.mode === 'mod-first') {
    activeTab.value = 'mod'
    if (easyQGL.lockedGameVersion) modGameVersion.value = easyQGL.lockedGameVersion
    if (easyQGL.lockedLoader) modLoader.value = easyQGL.lockedLoader
  }
})

async function loadVersions() {
  loading.value = true
  error.value = ''
  try {
    versions.value = await GetVersionManifest()
  } catch (e) {
    error.value = t('download.getVersionsFailed') + cleanError(e)
  } finally {
    loading.value = false
  }
}

async function loadJavaList() {
  try {
    javaList.value = await GetJavaDownloadList()
    installedJavaList.value = await SearchJava()
  } catch (e) {
    console.error('加载Java下载列表失败:', e)
  }
}

async function loadModCategories() {
  try {
    modCategories.value = await GetModrinthCategories()
  } catch (e) {
    console.error('加载Mod分类失败:', e)
  }
}

async function loadInstalledVersions() {
  try {
    installedGameVersions.value = await GetInstalledVersions()
  } catch (e) {
    console.error('加载已安装版本失败:', e)
  }
}

function selectVersion(ver) {
  selectedVersion.value = ver
  customName.value = ver.id
  addSuccess.value = false
  error.value = ''
  selectedLoader.value = null
  showAdvanced.value = false
}

function backToList() {
  selectedVersion.value = null
  customName.value = ''
  addSuccess.value = false
  error.value = ''
  selectedLoader.value = null
  showAdvanced.value = false
}

async function handleAddToList() {
  if (!selectedVersion.value) return
  if (!customName.value.trim()) {
    error.value = t('download.enterGameNameError')
    return
  }

  adding.value = true
  error.value = ''

  try {
    if (selectedLoader.value) {
      await AddToDownloadListWithLoader(
        selectedVersion.value.id,
        selectedVersion.value.url,
        customName.value.trim(),
        selectedVersion.value.type,
        selectedLoader.value.name,
        selectedLoader.value.forgeVersion || selectedLoader.value.version,
        selectedLoader.value.optifineType || '',
        selectedLoader.value.patch || ''
      )
    } else {
      await AddToDownloadList(
        selectedVersion.value.id,
        selectedVersion.value.url,
        customName.value.trim(),
        selectedVersion.value.type
      )
    }
    addSuccess.value = true
    setTimeout(() => { backToList() }, 1200)
  } catch (e) {
    error.value = cleanError(e)
  } finally {
    adding.value = false
  }
}

const filteredVersions = ref([])
function updateFilter() {
  if (filterType.value === 'all') {
    filteredVersions.value = versions.value
  } else {
    filteredVersions.value = versions.value.filter(v => v.type === filterType.value)
  }
}

watch(() => versions.value, () => { updateFilter() }, { immediate: true })
watch(() => filterType.value, () => { updateFilter() })

function isJavaInstalled(majorVer) {
  return installedJavaList.value.some(j => j.majorVer === majorVer)
}

function getInstalledJavaInfo(majorVer) {
  const found = installedJavaList.value.find(j => j.majorVer === majorVer)
  return found ? `${found.version} ${found.is64Bit ? t('settings.bit64') : t('settings.bit32')}` : ''
}

async function handleDownloadJava(majorVer) {
  try {
    await AddJavaToDownloadList(majorVer)
  } catch (e) {
    error.value = cleanError(e)
  }
}

async function searchMods(page = 0) {
  modSearching.value = true
  modSearchPage.value = page
  error.value = ''
  try {
    const query = modQuery.value.trim()
    const isChineseQuery = /[\u4e00-\u9fa5]/.test(query)

    let result
    if (isChineseQuery && query) {
      const englishSlugs = await SearchModsByChineseName(query)
      if (englishSlugs && englishSlugs.length > 0) {
        result = await SearchMods(englishSlugs[0], modGameVersion.value, modLoader.value, modCategory.value, page, 20)
      } else {
        result = await SearchMods(query, modGameVersion.value, modLoader.value, modCategory.value, page, 20)
      }
    } else {
      result = await SearchMods(query, modGameVersion.value, modLoader.value, modCategory.value, page, 20)
    }

    if (result) {
      modSearchResults.value = result.hits || []
      modSearchTotal.value = result.totalHits || 0
    } else {
      modSearchResults.value = []
      modSearchTotal.value = 0
    }

    if (modSearchResults.value.length > 0) {
      for (const m of modSearchResults.value) getModChineseNameCached(m)
    }
  } catch (e) {
    error.value = cleanError(e)
    modSearchResults.value = []
    modSearchTotal.value = 0
  } finally {
    modSearching.value = false
  }
}

async function getModChineseName(mod) {
  const key = mod.slug || mod.title || ''
  if (!key) return ''
  try {
    const chinese = await TranslateModName(key)
    return chinese && chinese !== key ? chinese : ''
  } catch (e) {
    console.error('翻译Mod名称失败:', e)
    return ''
  }
}

const modTranslationCache = ref({})

async function getModChineseNameCached(mod) {
  const key = mod.slug || mod.project_id || ''
  if (!key) return ''
  if (modTranslationCache.value[key] !== undefined) return modTranslationCache.value[key]
  const result = await getModChineseName(mod)
  modTranslationCache.value[key] = result
  return result
}

async function selectMod(mod) {
  selectedMod.value = mod
  modVersions.value = []
  modDependencies.value = []
  modVersionsLoading.value = true
  modDepsLoading.value = true

  try {
    const versions = await GetModVersions(mod.project_id, modGameVersion.value, modLoader.value)
    modVersions.value = versions || []
  } catch (e) {
    modVersions.value = []
  } finally {
    modVersionsLoading.value = false
  }

  if (modVersions.value && modVersions.value.length > 0) {
    try {
      const deps = await GetModDependencies(modVersions.value[0].id)
      modDependencies.value = deps || []
    } catch (e) {
      console.error('加载Mod依赖失败:', e)
      modDependencies.value = []
    } finally {
      modDepsLoading.value = false
    }
  } else {
    modDepsLoading.value = false
  }
}

function backToModList() {
  selectedMod.value = null
  modVersions.value = []
  modDependencies.value = []
}

async function handleAddModToDownloadList(versionId) {
  try {
    const dir = await SelectModSaveDir()
    if (!dir) return
    await AddModToDownloadList(versionId, dir)
    recordEasyQGLMod(versionId)
  } catch (e) {
    error.value = cleanError(e)
  }
}

async function handleAddModToDefaultDir(versionId) {
  try {
    const dir = modSavePath.value || await GetDefaultModDir(modGameVersion.value)
    await AddModToDownloadList(versionId, dir)
    recordEasyQGLMod(versionId)
  } catch (e) {
    error.value = cleanError(e)
  }
}

async function handleAddModToEasyList(versionId, versionInfo) {
  try {
    recordEasyQGLMod(versionId, versionInfo)

    if (easyQGL.lockedGameVersion) modGameVersion.value = easyQGL.lockedGameVersion
    if (easyQGL.lockedLoader) modLoader.value = easyQGL.lockedLoader

    selectedMod.value = null
    modVersions.value = []
    modDependencies.value = []
  } catch (e) {
    error.value = cleanError(e)
  }
}

function formatDownloads(num) {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return String(num)
}

const modpackTotalPages = computed(() => Math.ceil(modpackSearchTotal.value / 20))

async function searchModpacks(page) {
  modpackSearching.value = true
  error.value = ''
  modpackSearchPage.value = page
  try {
    const result = await SearchModpacks(modpackQuery.value, modpackGameVersion.value, page, 20)
    modpackSearchResults.value = result.hits || []
    modpackSearchTotal.value = result.total_hits || 0
  } catch (e) {
    error.value = cleanError(e)
    modpackSearchResults.value = []
  } finally {
    modpackSearching.value = false
  }
}

async function selectModpack(mod) {
  selectedModpack.value = mod
  modpackVersions.value = []
  modpackVersionsLoading.value = true
  error.value = ''
  try {
    modpackVersions.value = await GetModpackVersions(mod.project_id)
  } catch (e) {
    error.value = cleanError(e)
  } finally {
    modpackVersionsLoading.value = false
  }
}

function backToModpackList() {
  selectedModpack.value = null
  modpackVersions.value = []
  error.value = ''
}

async function handleAddModpackToDownloadList(versionId) {
  try {
    const name = selectedModpack.value?.title || ''
    await AddModpackToDownloadList(versionId, name)
  } catch (e) {
    error.value = cleanError(e)
  }
}

async function loadLoaderVersions() {
  loaderLoading.value = true
  loaderVersions.value = []
  error.value = ''
  try {
    const mcVer = selectedVersion.value?.id || ''
    if (!mcVer) {
      error.value = t('download.selectVersionFirst')
      loaderLoading.value = false
      return
    }

    let versions = []
    switch (loaderTab.value) {
      case 'forge': versions = await GetForgeVersions(mcVer); break
      case 'fabric': versions = await GetFabricVersions(mcVer); break
      case 'neoforge': versions = await GetNeoForgeVersions(mcVer); break
      case 'optifine': versions = await GetOptiFineVersions(mcVer); break
    }
    loaderVersions.value = versions || []

    // CheckLoaderInstalled 只依赖 (mcVer, loaderTab)，与具体版本号无关，查一次即可
    let installed = false
    try {
      installed = await CheckLoaderInstalled(mcVer, loaderTab.value)
    } catch (e) {
      console.error('检查加载器安装状态失败:', e)
      installed = false
    }
    loaderVersions.value.forEach(v => { v.isInstalled = installed })
  } catch (e) {
    error.value = cleanError(e)
    loaderVersions.value = []
  } finally {
    loaderLoading.value = false
  }
}

function selectLoader(loader) {
  if (selectedLoader.value && selectedLoader.value.name === loader.name && selectedLoader.value.version === loader.version) {
    selectedLoader.value = null
  } else {
    selectedLoader.value = loader
  }
}

function isSelectedLoader(loader) {
  return selectedLoader.value && selectedLoader.value.name === loader.name && selectedLoader.value.version === loader.version
}

function clearLoaderSelection() {
  selectedLoader.value = null
}

watch(() => loaderTab.value, () => {
  if (showAdvanced.value) loadLoaderVersions()
})

watch(() => showAdvanced.value, (val) => {
  if (val && loaderVersions.value.length === 0) loadLoaderVersions()
})

const totalPages = computed(() => Math.ceil(modSearchTotal.value / 20))
</script>

<template>
  <div class="download-page">
    <div class="top-bar">
      <button class="btn btn-outline" @click="easyQGL.active ? emit('navigate', 'easyqgl') : emit('navigate', 'main')">
        &#x2190; {{ easyQGL.active ? t('download.backToEasyQGL') : t('download.backToMain') }}
      </button>
      <h2 class="page-title">{{ t('download.title') }}</h2>
      <div v-if="easyQGL.active" class="easy-mode-badge">{{ t('download.easyMode') }}</div>
    </div>

    <div v-if="!easyQGL.active" class="tab-bar">
      <button class="tab-btn" :class="{ active: activeTab === 'game' }" @click="activeTab = 'game'">{{ t('download.gameVersion') }}</button>
      <button class="tab-btn" :class="{ active: activeTab === 'mod' }" @click="activeTab = 'mod'">{{ t('download.mod') }}</button>
      <button class="tab-btn" :class="{ active: activeTab === 'modpack' }" @click="activeTab = 'modpack'">{{ t('download.modpack') }}</button>
      <button class="tab-btn" :class="{ active: activeTab === 'java' }" @click="activeTab = 'java'">{{ t('download.javaRuntime') }}</button>
    </div>

    <div v-if="activeTab === 'game'" class="content-area">
      <div class="glass-container">
      <div v-if="error && activeTab === 'game'" class="error-msg">{{ error }}</div>

      <div v-if="!selectedVersion">
        <div v-if="loading" class="loading-area">
          <div class="spin" style="font-size: 32px;">&#x2697;</div>
          <p>{{ t('download.gettingVersionList') }}</p>
        </div>

        <div v-else-if="versions.length > 0">
          <div class="filter-bar">
            <button class="filter-btn" :class="{ active: filterType === 'release' }" @click="filterType = 'release'">{{ t('download.release') }}</button>
            <button class="filter-btn" :class="{ active: filterType === 'snapshot' }" @click="filterType = 'snapshot'">{{ t('download.snapshot') }}</button>
            <button class="filter-btn" :class="{ active: filterType === 'all' }" @click="filterType = 'all'">{{ t('download.all') }}</button>
          </div>

          <div class="version-grid">
            <div v-for="ver in filteredVersions" :key="ver.id" class="version-card" @click="selectVersion(ver)">
              <div class="version-id">{{ ver.id }}</div>
              <div class="version-type-badge" :class="ver.type">
                {{ ver.type === 'release' ? t('download.release') : t('download.snapshot') }}
              </div>
              <div class="version-date">{{ ver.releaseTime?.split('T')[0] }}</div>
            </div>
          </div>
        </div>

        <div v-else class="empty-area">
          <p>{{ t('download.noVersions') }}</p>
          <button class="btn btn-primary" @click="loadVersions">{{ t('download.retry') }}</button>
        </div>
      </div>

      <div v-else>
        <button class="back-link" @click="backToList">&#x2190; {{ t('download.backToVersionList') }}</button>

        <div class="download-detail fade-in">
          <div class="detail-header">
            <h2>{{ selectedVersion.id }}</h2>
            <span class="version-type-badge" :class="selectedVersion.type">
              {{ selectedVersion.type === 'release' ? t('download.release') : t('download.snapshot') }}
            </span>
          </div>

          <div class="form-group">
            <label>{{ t('download.gameName') }}</label>
            <input v-model="customName" class="input" :placeholder="t('download.enterGameName')" :disabled="adding" />
          </div>

          <div class="advanced-section">
            <button class="advanced-toggle" @click="showAdvanced = !showAdvanced">
              {{ showAdvanced ? t('download.collapseAdvanced') : t('download.advancedOptions') }}
              <span v-if="selectedLoader" class="selected-loader-hint">
                - {{ t('download.selected') }} {{ selectedLoader.displayName }} {{ selectedLoader.version }}
              </span>
            </button>

            <div v-if="showAdvanced" class="advanced-content">
              <div v-if="selectedLoader" class="selected-loader-bar">
                <span>{{ t('download.selectedLoader') }} <strong>{{ selectedLoader.displayName }} {{ selectedLoader.version }}</strong></span>
                <button class="btn btn-outline btn-sm" @click="clearLoaderSelection">{{ t('download.cancelSelection') }}</button>
              </div>

              <div class="loader-tabs">
                <button class="loader-tab-btn" :class="{ active: loaderTab === 'forge' }" @click="loaderTab = 'forge'">Forge</button>
                <button class="loader-tab-btn" :class="{ active: loaderTab === 'fabric' }" @click="loaderTab = 'fabric'">Fabric</button>
                <button class="loader-tab-btn" :class="{ active: loaderTab === 'neoforge' }" @click="loaderTab = 'neoforge'">NeoForge</button>
                <button class="loader-tab-btn" :class="{ active: loaderTab === 'optifine' }" @click="loaderTab = 'optifine'">OptiFine</button>
              </div>

              <div v-if="loaderLoading" class="loading-area" style="padding: 30px 0;">
                <div class="spin">&#x2697;</div>
                <p>{{ t('download.gettingLoaderVersions', { loader: loaderTab }) }}</p>
              </div>

              <div v-else-if="loaderVersions.length > 0" class="loader-list">
                <div v-for="lv in loaderVersions" :key="lv.version" class="loader-item" :class="{ selected: isSelectedLoader(lv) }" @click="selectLoader(lv)">
                  <div class="loader-item-info">
                    <div class="loader-item-version">{{ lv.version }}</div>
                    <div class="loader-item-meta">
                      <span v-if="lv.stable" class="loader-tag stable">{{ t('download.recommended') }}</span>
                      <span v-if="lv.isPreview" class="loader-tag preview">{{ t('download.preview') }}</span>
                    </div>
                  </div>
                  <div class="loader-item-actions">
                    <button class="btn btn-sm" :class="isSelectedLoader(lv) ? 'btn-primary' : 'btn-outline'">
                      {{ isSelectedLoader(lv) ? t('download.selectedTag') : t('download.selectTag') }}
                    </button>
                  </div>
                </div>
              </div>

              <div v-else class="empty-area" style="padding: 30px 0;">
                <p>{{ t('download.noLoaderVersions') }}</p>
                <button class="btn btn-outline btn-sm" @click="loadLoaderVersions">{{ t('download.retry') }}</button>
              </div>
            </div>
          </div>

          <div v-if="addSuccess" class="success-msg">
            {{ t('download.addedToList') }}{{ t('download.willReturn') || '即将返回...' }}
          </div>

          <div v-if="error && activeTab === 'game'" class="error-msg">{{ error }}</div>

          <button class="btn btn-primary btn-large" :disabled="adding || !customName.trim()" @click="handleAddToList">
            {{ adding
              ? t('download.adding')
              : (selectedLoader
                ? t('download.addToDownloadList') + '（' + selectedLoader.displayName + ' ' + selectedLoader.version + '）'
                : t('download.addToDownloadList'))
            }}
          </button>
        </div>
      </div>
      </div>
    </div>

    <div v-if="activeTab === 'mod'" class="content-area">
      <div class="glass-container">
      <div v-if="error && activeTab === 'mod'" class="error-msg">{{ error }}</div>

      <div v-if="!selectedMod">
        <div class="mod-search-bar">
          <input v-model="modQuery" class="input mod-search-input" placeholder="搜索 Mod（支持中文/英文，从 Modrinth）..." @keyup.enter="searchMods(0)" />
          <button class="btn btn-primary" :disabled="modSearching" @click="searchMods(0)">
            {{ modSearching ? t('download.searching') : t('download.search') }}
          </button>
        </div>

        <div class="mod-filters">
          <select v-model="modGameVersion" class="input mod-filter-select" :disabled="easyQGL.active && easyQGL.lockedGameVersion" @change="searchMods(0)">
            <option value="">全部版本</option>
            <option v-for="v in installedGameVersions" :key="v.folderName" :value="v.version">{{ v.version }}</option>
            <option v-for="v in versions.slice(0, 30)" :key="v.id" :value="v.id">{{ v.id }}</option>
          </select>
          <select v-model="modLoader" class="input mod-filter-select" :disabled="easyQGL.active && easyQGL.lockedLoader" @change="searchMods(0)">
            <option value="">{{ t('download.allLoaders') }}</option>
            <option value="forge">Forge</option>
            <option value="fabric">Fabric</option>
            <option value="neoforge">NeoForge</option>
          </select>
          <select v-model="modCategory" class="input mod-filter-select" @change="searchMods(0)">
            <option value="">{{ t('download.allCategories') }}</option>
            <option v-for="cat in modCategories" :key="cat.name" :value="cat.name">{{ cat.name }}</option>
          </select>
        </div>

        <div v-if="modSearching" class="loading-area" style="padding: 40px 0;">
          <div class="spin" style="font-size: 32px;">&#x2697;</div>
          <p>{{ t('download.searching') }}</p>
        </div>

        <div v-else-if="modSearchResults.length > 0">
          <div class="mod-result-count">{{ t('download.modSearchResults', { total: modSearchTotal }) }}</div>
          <div class="mod-grid">
            <div v-for="mod in modSearchResults" :key="mod.project_id" class="mod-card" @click="selectMod(mod)">
              <div class="mod-card-icon">
                <img v-if="mod.icon_url" :src="mod.icon_url" alt="" />
                <span v-else class="mod-icon-placeholder">{{ mod.title?.[0] || '?' }}</span>
              </div>
              <div class="mod-card-info">
                <div class="mod-card-title">{{ mod.title }}</div>
                <div class="mod-card-chinese" v-if="modTranslationCache[mod.slug || mod.project_id]">
                  {{ modTranslationCache[mod.slug || mod.project_id] }}
                </div>
                <div class="mod-card-desc">{{ mod.description }}</div>
                <div class="mod-card-meta">
                  <span class="mod-downloads">&#x2B07; {{ formatDownloads(mod.downloads) }}</span>
                  <span v-for="l in mod.loaders?.slice(0, 2)" :key="l" class="mod-loader-tag">{{ l }}</span>
                </div>
              </div>
            </div>
          </div>

          <div v-if="totalPages > 1" class="pagination">
            <button class="btn btn-outline btn-sm" :disabled="modSearchPage <= 0" @click="searchMods(modSearchPage - 1)">{{ t('download.pagePrev') }}</button>
            <span class="page-info">{{ modSearchPage + 1 }} / {{ totalPages }}</span>
            <button class="btn btn-outline btn-sm" :disabled="modSearchPage >= totalPages - 1" @click="searchMods(modSearchPage + 1)">{{ t('download.pageNext') }}</button>
          </div>
        </div>

        <div v-else-if="modQuery && !modSearching" class="empty-area">
          <p>{{ t('download.noResults') }}，{{ t('download.tryOtherKeywords') }}</p>
        </div>

        <div v-else class="empty-area">
          <p>{{ t('download.enterKeywords') }}</p>
        </div>
      </div>

      <div v-else>
        <button class="back-link" @click="backToModList">&#x2190; {{ t('download.backToModList') }}</button>

        <div class="mod-detail fade-in">
          <div class="mod-detail-header">
            <div class="mod-detail-icon">
              <img v-if="selectedMod.icon_url" :src="selectedMod.icon_url" alt="" />
              <span v-else class="mod-icon-placeholder large">{{ selectedMod.title?.[0] || '?' }}</span>
            </div>
            <div class="mod-detail-title-area">
              <h2>{{ selectedMod.title }}</h2>
              <div class="mod-detail-meta">
                <span class="mod-downloads">&#x2B07; {{ formatDownloads(selectedMod.downloads) }}</span>
                <span v-for="l in selectedMod.loaders" :key="l" class="mod-loader-tag">{{ l }}</span>
              </div>
            </div>
          </div>

          <p class="mod-detail-desc">{{ selectedMod.description }}</p>

          <div v-if="modDependencies.length > 0" class="mod-deps-section">
            <h3>{{ t('download.dependencies') }}</h3>
            <div class="mod-deps-list">
              <div v-for="dep in modDependencies" :key="dep.projectId" class="mod-dep-item">
                <div class="mod-dep-icon">
                  <img v-if="dep.iconUrl" :src="dep.iconUrl" alt="" />
                  <span v-else class="mod-icon-placeholder small">{{ dep.projectName?.[0] || '?' }}</span>
                </div>
                <div class="mod-dep-info">
                  <span class="mod-dep-name">{{ dep.projectName }}</span>
                  <span class="mod-dep-type" :class="dep.dependencyType">
                    {{ dep.dependencyType === 'required' ? t('download.required') : dep.dependencyType === 'optional' ? t('download.optional') : t('download.incompatible') }}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <h3>{{ t('download.versions') }}</h3>
          <div v-if="modVersionsLoading" class="loading-area" style="padding: 20px 0;">
            <div class="spin">&#x2697;</div>
            <p>{{ t('download.loadingVersions') }}</p>
          </div>
          <div v-else-if="modVersions.length > 0" class="mod-version-list">
            <div v-for="mv in modVersions" :key="mv.id" class="mod-version-item">
              <div class="mod-version-info">
                <div class="mod-version-name">{{ mv.name || mv.version_number }}</div>
                <div class="mod-version-meta">
                  <span v-for="gv in mv.game_versions?.slice(0, 2)" :key="gv" class="mod-gv-tag">{{ gv }}</span>
                  <span v-for="l in mv.loaders" :key="l" class="mod-loader-tag">{{ l }}</span>
                </div>
              </div>
              <div class="mod-version-actions">
                <template v-if="easyQGL.active">
                  <button class="btn btn-easy-orange btn-sm" @click="handleAddModToEasyList(mv.id, mv)">
                    {{ t('download.addToList') }}
                  </button>
                </template>
                <template v-else>
                  <button class="btn btn-primary btn-sm" @click="handleAddModToDownloadList(mv.id)">
                    {{ t('download.selectLocationAndDownload') }}
                  </button>
                  <button class="btn btn-outline btn-sm" @click="handleAddModToDefaultDir(mv.id)">
                    {{ t('download.quickDownload') }}
                  </button>
                </template>
              </div>
            </div>
          </div>
          <div v-else class="empty-area" style="padding: 20px 0;">
            <p>{{ t('download.noVersionsAvailable') }}</p>
          </div>
        </div>
      </div>
      </div>
    </div>

    <div v-if="activeTab === 'modpack'" class="content-area">
      <div class="glass-container">
      <div v-if="error && activeTab === 'modpack'" class="error-msg">{{ error }}</div>

      <div v-if="!selectedModpack">
        <div class="mod-search-bar">
          <input v-model="modpackQuery" class="input mod-search-input" :placeholder="t('download.modpackSearchPlaceholder')" @keyup.enter="searchModpacks(0)" />
          <button class="btn btn-primary" :disabled="modpackSearching" @click="searchModpacks(0)">
            {{ modpackSearching ? t('download.searching') : t('download.search') }}
          </button>
        </div>

        <div class="mod-filters">
          <select v-model="modpackGameVersion" class="input mod-filter-select" @change="searchModpacks(0)">
            <option value="">{{ t('download.allVersions') }}</option>
            <option v-for="v in installedGameVersions" :key="v.folderName" :value="v.version">{{ v.version }}</option>
            <option v-for="v in versions.slice(0, 30)" :key="v.id" :value="v.id">{{ v.id }}</option>
          </select>
        </div>

        <div v-if="modpackSearching" class="loading-area" style="padding: 40px 0;">
          <div class="spin" style="font-size: 32px;">&#x2697;</div>
          <p>{{ t('download.searching') }}</p>
        </div>

        <div v-else-if="modpackSearchResults.length > 0">
          <div class="mod-result-count">{{ t('download.modSearchResults', { total: modpackSearchTotal }) }}</div>
          <div class="mod-grid">
            <div v-for="mod in modpackSearchResults" :key="mod.project_id" class="mod-card" @click="selectModpack(mod)">
              <div class="mod-card-icon">
                <img v-if="mod.icon_url" :src="mod.icon_url" alt="" />
                <span v-else class="mod-icon-placeholder">{{ mod.title?.[0] || '?' }}</span>
              </div>
              <div class="mod-card-info">
                <div class="mod-card-title">{{ mod.title }}</div>
                <div class="mod-card-desc">{{ mod.description }}</div>
                <div class="mod-card-meta">
                  <span class="mod-downloads">&#x2B07; {{ formatDownloads(mod.downloads) }}</span>
                  <span v-for="gv in mod.versions?.slice(0, 3)" :key="gv" class="mod-gv-tag">{{ gv }}</span>
                </div>
              </div>
            </div>
          </div>

          <div v-if="modpackTotalPages > 1" class="pagination">
            <button class="btn btn-outline btn-sm" :disabled="modpackSearchPage <= 0" @click="searchModpacks(modpackSearchPage - 1)">{{ t('download.pagePrev') }}</button>
            <span class="page-info">{{ modpackSearchPage + 1 }} / {{ modpackTotalPages }}</span>
            <button class="btn btn-outline btn-sm" :disabled="modpackSearchPage >= modpackTotalPages - 1" @click="searchModpacks(modpackSearchPage + 1)">{{ t('download.pageNext') }}</button>
          </div>
        </div>

        <div v-else-if="modpackQuery && !modpackSearching" class="empty-area">
          <p>{{ t('download.noResults') }}，{{ t('download.tryOtherKeywords') }}</p>
        </div>

        <div v-else class="empty-area">
          <p>{{ t('download.modpackEnterKeywords') }}</p>
        </div>
      </div>

      <div v-else>
        <button class="back-link" @click="backToModpackList">&#x2190; {{ t('download.backToModpackList') }}</button>

        <div class="mod-detail fade-in">
          <div class="mod-detail-header">
            <div class="mod-detail-icon">
              <img v-if="selectedModpack.icon_url" :src="selectedModpack.icon_url" alt="" />
              <span v-else class="mod-icon-placeholder large">{{ selectedModpack.title?.[0] || '?' }}</span>
            </div>
            <div class="mod-detail-title-area">
              <h2>{{ selectedModpack.title }}</h2>
              <div class="mod-detail-meta">
                <span class="mod-downloads">&#x2B07; {{ formatDownloads(selectedModpack.downloads) }}</span>
              </div>
            </div>
          </div>

          <p class="mod-detail-desc">{{ selectedModpack.description }}</p>

          <h3>{{ t('download.versions') }}</h3>
          <div v-if="modpackVersionsLoading" class="loading-area" style="padding: 20px 0;">
            <div class="spin">&#x2697;</div>
            <p>{{ t('download.loadingVersions') }}</p>
          </div>
          <div v-else-if="modpackVersions.length > 0" class="mod-version-list">
            <div v-for="mv in modpackVersions" :key="mv.id" class="mod-version-item">
              <div class="mod-version-info">
                <div class="mod-version-name">{{ mv.name || mv.version_number }}</div>
                <div class="mod-version-meta">
                  <span v-for="gv in mv.game_versions?.slice(0, 3)" :key="gv" class="mod-gv-tag">{{ gv }}</span>
                  <span v-for="l in mv.loaders" :key="l" class="mod-loader-tag">{{ l }}</span>
                </div>
              </div>
              <div class="mod-version-actions">
                <button class="btn btn-primary btn-sm" @click="handleAddModpackToDownloadList(mv.id, mv)">
                  {{ t('download.addToList') }}
                </button>
              </div>
            </div>
          </div>
          <div v-else class="empty-area" style="padding: 20px 0;">
            <p>{{ t('download.noVersionsAvailable') }}</p>
          </div>
        </div>
      </div>
      </div>
    </div>

    <div v-if="activeTab === 'java'" class="content-area">
      <div class="glass-container">
      <div v-if="error && activeTab === 'java'" class="error-msg">{{ error }}</div>

      <div class="java-section">
        <div class="java-hint">{{ t('download.javaHint') }}</div>

        <div class="java-download-list">
          <div v-for="j in javaList" :key="j.majorVer" class="java-download-card">
            <div class="java-card-left">
              <div class="java-card-icon" :class="'java-icon-' + j.majorVer">{{ j.majorVer }}</div>
              <div class="java-card-info">
                <div class="java-card-name">{{ j.name }}</div>
                <div class="java-card-status">
                  <span v-if="isJavaInstalled(j.majorVer)" class="java-installed">
                    {{ t('download.installed') }}: {{ getInstalledJavaInfo(j.majorVer) }}
                  </span>
                  <span v-else class="java-not-installed">{{ t('download.javaNotInstalled') }}</span>
                  <span v-if="j.isWebPage" class="java-webpage-tag">{{ t('download.webDownload') }}</span>
                  <span v-else-if="j.isMSI" class="java-msi-tag">{{ t('download.msiPackage') }}</span>
                  <span v-else-if="j.isZip" class="java-zip-tag">{{ t('download.zipPackage') }}</span>
                </div>
              </div>
            </div>

            <div class="java-card-right">
              <button class="btn btn-primary btn-sm" :disabled="isJavaInstalled(j.majorVer)" @click="handleDownloadJava(j.majorVer)">
                <template v-if="isJavaInstalled(j.majorVer)">{{ t('download.installed') }}</template>
                <template v-else>{{ t('download.downloadJava') }}</template>
              </button>
            </div>
          </div>
        </div>
      </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.download-page {
  width: 100%;
  height: 100%;
  display: flex;
  flex-direction: column;
  background: transparent;
  position: relative;
  z-index: 2;
}
</style>
<style>
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

.easy-mode-badge {
  margin-left: auto;
  padding: 4px 12px;
  background: var(--easy-orange, #FF9800);
  color: white;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 600;
}

.btn-easy-orange {
  background: var(--easy-orange, #FF9800);
  border-color: var(--easy-orange, #FF9800);
  color: white;
}

.btn-easy-orange:hover {
  background: var(--easy-orange-dark, #F57C00);
  border-color: var(--easy-orange-dark, #F57C00);
}

.tab-bar {
  display: flex;
  gap: 0;
  padding: 0 24px;
  border-bottom: 1px solid var(--border);
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
}

.tab-btn {
  padding: 12px 24px;
  border: none;
  background: none;
  font-size: 14px;
  font-weight: 500;
  color: var(--text-secondary);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  transition: all 0.15s;
}

.tab-btn:hover { color: var(--primary); }

.tab-btn.active {
  color: var(--primary);
  border-bottom-color: var(--primary);
  font-weight: 600;
}

.content-area {
  flex: 1;
  overflow-y: auto;
  padding: 20px;
}

.glass-container {
  background: var(--glass-bg);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border-radius: 14px;
  border: 1px solid var(--glass-border);
  padding: 20px;
}

.loading-area {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 0;
  color: var(--text-secondary);
  gap: 12px;
  background: var(--glass-bg-light);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 10px;
  border: 1px solid var(--glass-border);
}

.spin {
  animation: spin 1s linear infinite;
  display: inline-block;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.error-msg {
  background: color-mix(in srgb, var(--danger) 10%, var(--glass-bg-heavy));
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  color: var(--danger);
  padding: 10px 14px;
  border-radius: 8px;
  font-size: 13px;
  margin-bottom: 16px;
  border: 1px solid color-mix(in srgb, var(--danger) 25%, transparent);
}

.success-msg {
  background: color-mix(in srgb, var(--success) 10%, var(--glass-bg-heavy));
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  color: var(--success);
  padding: 10px 14px;
  border-radius: 8px;
  font-size: 13px;
  margin-bottom: 16px;
  border: 1px solid color-mix(in srgb, var(--success) 25%, transparent);
}

.filter-bar {
  display: flex;
  gap: 8px;
  margin-bottom: 20px;
}

.filter-btn {
  padding: 6px 16px;
  border: 1.5px solid var(--border);
  border-radius: 20px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  color: var(--text-secondary);
  font-size: 13px;
  cursor: pointer;
  transition: all 0.15s;
}

.filter-btn:hover {
  border-color: var(--primary);
  color: var(--primary);
}

.filter-btn.active {
  background: var(--primary);
  border-color: var(--primary);
  color: white;
}

.version-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: 12px;
}

.version-card {
  padding: 16px;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1.5px solid var(--border);
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.15s;
}

.version-card:hover {
  border-color: var(--primary);
  box-shadow: 0 2px 12px color-mix(in srgb, var(--primary) 15%, transparent);
}

.version-id {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 6px;
}

.version-type-badge {
  display: inline-block;
  font-size: 11px;
  padding: 2px 8px;
  border-radius: 10px;
  font-weight: 500;
}

.version-type-badge.release {
  background: color-mix(in srgb, var(--success) 15%, transparent);
  color: var(--success);
}

.version-type-badge.snapshot {
  background: color-mix(in srgb, var(--warning, #FF9800) 15%, transparent);
  color: var(--warning, #E65100);
}

.version-date {
  font-size: 12px;
  color: var(--text-light);
  margin-top: 6px;
}

.empty-area {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 60px 0;
  gap: 16px;
  color: var(--text-secondary);
  background: var(--glass-bg-light);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 10px;
  border: 1px dashed var(--border);
}

.back-link {
  background: none;
  border: none;
  color: var(--primary);
  font-size: 14px;
  cursor: pointer;
  padding: 4px 0;
  margin-bottom: 16px;
}

.back-link:hover { text-decoration: underline; }

.download-detail {
  max-width: 600px;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 12px;
  padding: 24px;
}

.detail-header {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 24px;
}

.detail-header h2 {
  font-size: 24px;
  font-weight: 700;
  color: var(--text);
}

.form-group { margin-bottom: 20px; }

.form-group label {
  display: block;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-secondary);
  margin-bottom: 6px;
}

.advanced-section {
  margin-bottom: 20px;
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: hidden;
}

.advanced-toggle {
  width: 100%;
  padding: 12px 16px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(16px);
  -webkit-backdrop-filter: blur(16px);
  border: none;
  font-size: 13px;
  color: var(--text-secondary);
  cursor: pointer;
  text-align: left;
  transition: background 0.15s;
}

.advanced-toggle:hover { background: var(--bg-secondary); }

.advanced-content {
  padding: 16px;
  border-top: 1px solid var(--border);
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}

.loader-tabs {
  display: flex;
  gap: 4px;
  margin-bottom: 16px;
}

.loader-tab-btn {
  padding: 6px 14px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  font-size: 12px;
  font-weight: 500;
  color: var(--text-secondary);
  cursor: pointer;
  transition: all 0.15s;
}

.loader-tab-btn:hover {
  border-color: var(--primary);
  color: var(--primary);
}

.loader-tab-btn.active {
  background: var(--primary);
  border-color: var(--primary);
  color: white;
}

.loader-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  max-height: 300px;
  overflow-y: auto;
}

.loader-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  border: 1px solid var(--border);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.15s;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}

.loader-item:hover { border-color: var(--primary); }
.loader-item.selected {
  border-color: var(--primary);
  background: var(--glass-bg-heavy);
}

.loader-item-info {
  display: flex;
  align-items: center;
  gap: 10px;
}

.loader-item-version {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
}

.loader-item-meta {
  display: flex;
  gap: 6px;
}

.loader-tag {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 4px;
  font-weight: 500;
}

.loader-tag.stable {
  background: color-mix(in srgb, var(--success) 15%, transparent);
  color: var(--success);
}

.loader-tag.preview {
  background: color-mix(in srgb, var(--warning, #FF9800) 15%, transparent);
  color: var(--warning, #E65100);
}

.loader-tag.installed {
  background: color-mix(in srgb, var(--primary) 15%, transparent);
  color: var(--primary);
}

.selected-loader-hint {
  font-size: 12px;
  color: var(--primary);
  font-weight: 500;
  margin-left: 8px;
}

.selected-loader-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 14px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid var(--primary);
  border-radius: 8px;
  margin-bottom: 12px;
  font-size: 13px;
  color: var(--text);
}

.loader-item-actions {
  display: flex;
  gap: 6px;
}

.mod-search-bar {
  display: flex;
  gap: 10px;
  margin-bottom: 16px;
}

.mod-search-input { flex: 1; }

.mod-filters {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
  flex-wrap: wrap;
}

.mod-filter-select {
  min-width: 140px;
  font-size: 13px;
}

.mod-result-count {
  font-size: 13px;
  color: var(--text-secondary);
  margin-bottom: 12px;
}

.mod-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
  gap: 12px;
}

.mod-card {
  display: flex;
  gap: 14px;
  padding: 14px 16px;
  border: 1.5px solid var(--border);
  border-radius: 10px;
  cursor: pointer;
  transition: all 0.15s;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}

.mod-card:hover {
  border-color: var(--primary);
  box-shadow: 0 2px 12px color-mix(in srgb, var(--primary) 15%, transparent);
}

.mod-card-icon {
  width: 48px;
  height: 48px;
  border-radius: 10px;
  overflow: hidden;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--glass-bg-heavy);
}

.mod-card-icon img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.mod-icon-placeholder {
  font-size: 20px;
  font-weight: 700;
  color: var(--primary);
}

.mod-icon-placeholder.small { font-size: 14px; }
.mod-icon-placeholder.large { font-size: 28px; }

.mod-card-info {
  flex: 1;
  min-width: 0;
}

.mod-card-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 4px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.mod-card-chinese {
  font-size: 12px;
  color: var(--primary-dark);
  margin-bottom: 4px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  font-weight: 500;
}

.mod-card-desc {
  font-size: 12px;
  color: var(--text-secondary);
  margin-bottom: 6px;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.mod-card-meta {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}

.mod-downloads {
  font-size: 11px;
  color: var(--text-light);
}

.mod-loader-tag {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 4px;
  background: color-mix(in srgb, var(--primary) 15%, transparent);
  color: var(--primary);
  font-weight: 500;
}

.mod-gv-tag {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 4px;
  background: color-mix(in srgb, var(--accent-purple, #9C27B0) 15%, transparent);
  color: var(--accent-purple, #7B1FA2);
  font-weight: 500;
}

.mod-detail {
  max-width: 800px;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 12px;
  padding: 24px;
}

.mod-detail-header {
  display: flex;
  gap: 20px;
  align-items: center;
  margin-bottom: 16px;
}

.mod-detail-icon {
  width: 64px;
  height: 64px;
  border-radius: 14px;
  overflow: hidden;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--glass-bg-heavy);
}

.mod-detail-icon img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.mod-detail-title-area h2 {
  font-size: 22px;
  font-weight: 700;
  color: var(--text);
  margin-bottom: 6px;
}

.mod-detail-meta {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}

.mod-detail-desc {
  font-size: 14px;
  color: var(--text-secondary);
  margin-bottom: 20px;
  line-height: 1.5;
}

.mod-deps-section {
  margin-bottom: 20px;
  padding: 14px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid color-mix(in srgb, var(--warning, #FF9800) 25%, transparent);
  border-radius: 10px;
}

.mod-deps-section h3 {
  font-size: 14px;
  font-weight: 600;
  color: var(--warning, #F57F17);
  margin-bottom: 10px;
}

.mod-deps-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.mod-dep-item {
  display: flex;
  align-items: center;
  gap: 10px;
}

.mod-dep-icon {
  width: 28px;
  height: 28px;
  border-radius: 6px;
  overflow: hidden;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--glass-bg-heavy);
}

.mod-dep-icon img {
  width: 100%;
  height: 100%;
  object-fit: cover;
}

.mod-dep-info {
  display: flex;
  align-items: center;
  gap: 8px;
}

.mod-dep-name {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
}

.mod-dep-type {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 4px;
  font-weight: 500;
}

.mod-dep-type.required {
  background: color-mix(in srgb, var(--danger) 15%, transparent);
  color: var(--danger);
}

.mod-dep-type.optional {
  background: color-mix(in srgb, var(--success) 15%, transparent);
  color: var(--success);
}

.mod-dep-type.incompatible {
  background: color-mix(in srgb, var(--danger) 20%, transparent);
  color: var(--danger);
}

.mod-version-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.mod-version-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 12px 16px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}

.mod-version-info {
  flex: 1;
  min-width: 0;
}

.mod-version-name {
  font-size: 13px;
  font-weight: 500;
  color: var(--text);
  margin-bottom: 4px;
}

.mod-version-meta {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
}

.mod-version-actions {
  display: flex;
  gap: 6px;
  flex-shrink: 0;
  margin-left: 12px;
}

.pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 16px;
  margin-top: 20px;
  padding: 12px 0;
}

.page-info {
  font-size: 13px;
  color: var(--text-secondary);
}

.java-section { max-width: 700px; }

.java-hint {
  font-size: 13px;
  color: var(--text-secondary);
  margin-bottom: 20px;
  padding: 10px 14px;
  background: var(--glass-bg-heavy);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border-radius: 8px;
}

.java-download-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.java-download-card {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 16px 20px;
  border: 1.5px solid var(--border);
  border-radius: 12px;
  transition: border-color 0.15s;
  background: var(--glass-bg);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
}

.java-download-card:hover { border-color: var(--primary); }

.java-card-left {
  display: flex;
  align-items: center;
  gap: 16px;
}

.java-card-icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 20px;
  font-weight: 700;
  color: white;
}

.java-icon-8 { background: var(--java-green, #43A047); }
.java-icon-17 { background: var(--java-orange, #FB8C00); }
.java-icon-21 { background: var(--java-teal, #00897B); }
.java-icon-26 { background: var(--java-gray, #546E7A); }

.java-card-name {
  font-size: 16px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 4px;
}

.java-card-status {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
}

.java-installed {
  color: var(--success);
  font-weight: 500;
}

.java-not-installed { color: var(--text-light); }

.java-webpage-tag,
.java-msi-tag,
.java-zip-tag {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 4px;
  font-weight: 500;
}

.java-webpage-tag { background: color-mix(in srgb, var(--primary) 15%, transparent); color: var(--primary); }
.java-msi-tag { background: color-mix(in srgb, var(--warning, #FF9800) 15%, transparent); color: var(--warning, #E65100); }
.java-zip-tag { background: color-mix(in srgb, var(--accent-purple, #9C27B0) 15%, transparent); color: var(--accent-purple, #7B1FA2); }

.java-card-right {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 140px;
  justify-content: flex-end;
}

h3 {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 12px;
}
</style>
