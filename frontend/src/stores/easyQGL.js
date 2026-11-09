import { reactive } from 'vue'

const easyQGLState = reactive({
  active: false,
  mode: '',
  firstMod: null,
  lockedGameVersion: '',
  lockedLoader: '',
  selectedMods: [],
  installStatus: 'idle',
  installMessage: '',
})

function resetState() {
  easyQGLState.active = false
  easyQGLState.mode = ''
  easyQGLState.firstMod = null
  easyQGLState.lockedGameVersion = ''
  easyQGLState.lockedLoader = ''
  easyQGLState.selectedMods = []
  easyQGLState.installStatus = 'idle'
  easyQGLState.installMessage = ''
}

export function useEasyQGL() {
  function enterModFirstMode() {
    resetState()
    easyQGLState.active = true
    easyQGLState.mode = 'mod-first'
  }

  function setFirstMod(mod, versionInfo) {
    easyQGLState.firstMod = mod

    if (versionInfo) {
      if (versionInfo.game_versions && versionInfo.game_versions.length > 0) {
        easyQGLState.lockedGameVersion = versionInfo.game_versions[0]
      }
      if (versionInfo.loaders && versionInfo.loaders.length > 0) {
        easyQGLState.lockedLoader = versionInfo.loaders[0].toLowerCase()
      }
      return
    }

    if (mod && mod.versions && mod.versions.length > 0) {
      const v = mod.versions[0]
      if (v.game_versions && v.game_versions.length > 0) {
        easyQGLState.lockedGameVersion = v.game_versions[0]
      }
      if (v.loaders && v.loaders.length > 0) {
        easyQGLState.lockedLoader = v.loaders[0].toLowerCase()
      }
    }
  }

  function addSelectedMod(mod) {
    // 同一 versionId 只保留一份，避免重复点击导致重复下载
    if (mod && mod.versionId && !easyQGLState.selectedMods.some(m => m.versionId === mod.versionId)) {
      easyQGLState.selectedMods.push(mod)
    }
  }

  function exitMode() {
    resetState()
  }

  return {
    state: easyQGLState,
    enterModFirstMode,
    setFirstMod,
    addSelectedMod,
    exitMode,
  }
}
