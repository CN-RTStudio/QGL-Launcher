export namespace main {
	
	export class DownloadItem {
	    id: string;
	    url: string;
	    customName: string;
	    type: string;
	    itemType: string;
	    javaMajor: number;
	    savePath: string;
	    loaderName: string;
	    loaderVersion: string;
	    optifineType: string;
	    optifinePatch: string;
	    status: string;
	    progress: number;
	    errorMsg: string;
	
	    static createFrom(source: any = {}) {
	        return new DownloadItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.url = source["url"];
	        this.customName = source["customName"];
	        this.type = source["type"];
	        this.itemType = source["itemType"];
	        this.javaMajor = source["javaMajor"];
	        this.savePath = source["savePath"];
	        this.loaderName = source["loaderName"];
	        this.loaderVersion = source["loaderVersion"];
	        this.optifineType = source["optifineType"];
	        this.optifinePatch = source["optifinePatch"];
	        this.status = source["status"];
	        this.progress = source["progress"];
	        this.errorMsg = source["errorMsg"];
	    }
	}
	export class DownloadProgress {
	    totalBytes: number;
	    downloadedBytes: number;
	    percentage: number;
	    currentFile: string;
	    status: string;
	
	    static createFrom(source: any = {}) {
	        return new DownloadProgress(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.totalBytes = source["totalBytes"];
	        this.downloadedBytes = source["downloadedBytes"];
	        this.percentage = source["percentage"];
	        this.currentFile = source["currentFile"];
	        this.status = source["status"];
	    }
	}
	export class ExternalAuthData {
	    serverUrl: string;
	    accessToken: string;
	    clientToken: string;
	    uuid: string;
	    username: string;
	    password: string;
	    serverName: string;
	
	    static createFrom(source: any = {}) {
	        return new ExternalAuthData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.serverUrl = source["serverUrl"];
	        this.accessToken = source["accessToken"];
	        this.clientToken = source["clientToken"];
	        this.uuid = source["uuid"];
	        this.username = source["username"];
	        this.password = source["password"];
	        this.serverName = source["serverName"];
	    }
	}
	export class GlobalConfig {
	    currentUser: string;
	    javaPath: string;
	    maxMemory: number;
	    minMemory: number;
	    minecraftDir: string;
	    portableMode: boolean;
	
	    static createFrom(source: any = {}) {
	        return new GlobalConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.currentUser = source["currentUser"];
	        this.javaPath = source["javaPath"];
	        this.maxMemory = source["maxMemory"];
	        this.minMemory = source["minMemory"];
	        this.minecraftDir = source["minecraftDir"];
	        this.portableMode = source["portableMode"];
	    }
	}
	export class InstalledVersionInfo {
	    folderName: string;
	    name: string;
	    version: string;
	    loader: string;
	    type: string;
	
	    static createFrom(source: any = {}) {
	        return new InstalledVersionInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.folderName = source["folderName"];
	        this.name = source["name"];
	        this.version = source["version"];
	        this.loader = source["loader"];
	        this.type = source["type"];
	    }
	}
	export class JavaDownloadInfo {
	    majorVer: number;
	    name: string;
	    url: string;
	    fileName: string;
	    isMSI: boolean;
	    isZip: boolean;
	    isWebPage: boolean;
	
	    static createFrom(source: any = {}) {
	        return new JavaDownloadInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.majorVer = source["majorVer"];
	        this.name = source["name"];
	        this.url = source["url"];
	        this.fileName = source["fileName"];
	        this.isMSI = source["isMSI"];
	        this.isZip = source["isZip"];
	        this.isWebPage = source["isWebPage"];
	    }
	}
	export class JavaEntry {
	    path: string;
	    version: string;
	    majorVer: number;
	    is64Bit: boolean;
	    isJDK: boolean;
	
	    static createFrom(source: any = {}) {
	        return new JavaEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.path = source["path"];
	        this.version = source["version"];
	        this.majorVer = source["majorVer"];
	        this.is64Bit = source["is64Bit"];
	        this.isJDK = source["isJDK"];
	    }
	}
	export class JavaVersionReq {
	    MinMajor: number;
	    MaxMajor: number;
	
	    static createFrom(source: any = {}) {
	        return new JavaVersionReq(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.MinMajor = source["MinMajor"];
	        this.MaxMajor = source["MaxMajor"];
	    }
	}
	export class LoaderInfo {
	    name: string;
	    displayName: string;
	    version: string;
	    mcVersion: string;
	    downloadUrl: string;
	    isInstalled: boolean;
	    stable: boolean;
	    category: string;
	    forgeVersion: string;
	    isPreview: boolean;
	    patch: string;
	    optifineType: string;
	
	    static createFrom(source: any = {}) {
	        return new LoaderInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.displayName = source["displayName"];
	        this.version = source["version"];
	        this.mcVersion = source["mcVersion"];
	        this.downloadUrl = source["downloadUrl"];
	        this.isInstalled = source["isInstalled"];
	        this.stable = source["stable"];
	        this.category = source["category"];
	        this.forgeVersion = source["forgeVersion"];
	        this.isPreview = source["isPreview"];
	        this.patch = source["patch"];
	        this.optifineType = source["optifineType"];
	    }
	}
	export class MCVersion {
	    id: string;
	    type: string;
	    url: string;
	    releaseTime: string;
	
	    static createFrom(source: any = {}) {
	        return new MCVersion(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.type = source["type"];
	        this.url = source["url"];
	        this.releaseTime = source["releaseTime"];
	    }
	}
	export class MSAuthData {
	    accessToken: string;
	    refreshToken: string;
	    mcAccessToken: string;
	    uuid: string;
	    username: string;
	    expiresAt: number;
	    mcExpiresAt: number;
	
	    static createFrom(source: any = {}) {
	        return new MSAuthData(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.accessToken = source["accessToken"];
	        this.refreshToken = source["refreshToken"];
	        this.mcAccessToken = source["mcAccessToken"];
	        this.uuid = source["uuid"];
	        this.username = source["username"];
	        this.expiresAt = source["expiresAt"];
	        this.mcExpiresAt = source["mcExpiresAt"];
	    }
	}
	export class ModCategory {
	    name: string;
	    icon: string;
	    project_type: string;
	
	    static createFrom(source: any = {}) {
	        return new ModCategory(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.icon = source["icon"];
	        this.project_type = source["project_type"];
	    }
	}
	export class ModDependency {
	    project_id: string;
	    version_id: string;
	    dependency_type: string;
	
	    static createFrom(source: any = {}) {
	        return new ModDependency(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.project_id = source["project_id"];
	        this.version_id = source["version_id"];
	        this.dependency_type = source["dependency_type"];
	    }
	}
	export class ModDependencyInfo {
	    projectId: string;
	    projectName: string;
	    iconUrl: string;
	    dependencyType: string;
	
	    static createFrom(source: any = {}) {
	        return new ModDependencyInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.projectId = source["projectId"];
	        this.projectName = source["projectName"];
	        this.iconUrl = source["iconUrl"];
	        this.dependencyType = source["dependencyType"];
	    }
	}
	export class ModDependencyResult {
	    projectId: string;
	    projectName: string;
	    iconUrl: string;
	    versionId: string;
	    dependencyType: string;
	
	    static createFrom(source: any = {}) {
	        return new ModDependencyResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.projectId = source["projectId"];
	        this.projectName = source["projectName"];
	        this.iconUrl = source["iconUrl"];
	        this.versionId = source["versionId"];
	        this.dependencyType = source["dependencyType"];
	    }
	}
	export class ModDetail {
	    id: string;
	    slug: string;
	    title: string;
	    description: string;
	    body: string;
	    icon_url: string;
	    downloads: number;
	    client_side: string;
	    server_side: string;
	    categories: string[];
	    game_versions: string[];
	    loaders: string[];
	    project_type: string;
	
	    static createFrom(source: any = {}) {
	        return new ModDetail(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.slug = source["slug"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.body = source["body"];
	        this.icon_url = source["icon_url"];
	        this.downloads = source["downloads"];
	        this.client_side = source["client_side"];
	        this.server_side = source["server_side"];
	        this.categories = source["categories"];
	        this.game_versions = source["game_versions"];
	        this.loaders = source["loaders"];
	        this.project_type = source["project_type"];
	    }
	}
	export class ModFile {
	    filename: string;
	    url: string;
	    size: number;
	    primary: boolean;
	    sha1: string;
	
	    static createFrom(source: any = {}) {
	        return new ModFile(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.filename = source["filename"];
	        this.url = source["url"];
	        this.size = source["size"];
	        this.primary = source["primary"];
	        this.sha1 = source["sha1"];
	    }
	}
	export class ModFileInfo {
	    fileName: string;
	    filePath: string;
	    isEnabled: boolean;
	    fileSize: number;
	
	    static createFrom(source: any = {}) {
	        return new ModFileInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.fileName = source["fileName"];
	        this.filePath = source["filePath"];
	        this.isEnabled = source["isEnabled"];
	        this.fileSize = source["fileSize"];
	    }
	}
	export class ModSearchResult {
	    project_id: string;
	    slug: string;
	    title: string;
	    description: string;
	    icon_url: string;
	    downloads: number;
	    client_side: string;
	    server_side: string;
	    categories: string[];
	    versions: string[];
	    loaders: string[];
	
	    static createFrom(source: any = {}) {
	        return new ModSearchResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.project_id = source["project_id"];
	        this.slug = source["slug"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.icon_url = source["icon_url"];
	        this.downloads = source["downloads"];
	        this.client_side = source["client_side"];
	        this.server_side = source["server_side"];
	        this.categories = source["categories"];
	        this.versions = source["versions"];
	        this.loaders = source["loaders"];
	    }
	}
	export class ModSearchResponse {
	    hits: ModSearchResult[];
	    total_hits: number;
	    offset: number;
	    limit: number;
	
	    static createFrom(source: any = {}) {
	        return new ModSearchResponse(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.hits = this.convertValues(source["hits"], ModSearchResult);
	        this.total_hits = source["total_hits"];
	        this.offset = source["offset"];
	        this.limit = source["limit"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class ModVersion {
	    id: string;
	    project_id: string;
	    name: string;
	    version_number: string;
	    game_versions: string[];
	    loaders: string[];
	    files: ModFile[];
	    dependencies: ModDependency[];
	    changelog: string;
	
	    static createFrom(source: any = {}) {
	        return new ModVersion(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.project_id = source["project_id"];
	        this.name = source["name"];
	        this.version_number = source["version_number"];
	        this.game_versions = source["game_versions"];
	        this.loaders = source["loaders"];
	        this.files = this.convertValues(source["files"], ModFile);
	        this.dependencies = this.convertValues(source["dependencies"], ModDependency);
	        this.changelog = source["changelog"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ServerConfig {
	    name: string;
	    version: string;
	    port: number;
	    maxMemory: number;
	    minMemory: number;
	    onlineMode: boolean;
	    serverDir: string;
	
	    static createFrom(source: any = {}) {
	        return new ServerConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.version = source["version"];
	        this.port = source["port"];
	        this.maxMemory = source["maxMemory"];
	        this.minMemory = source["minMemory"];
	        this.onlineMode = source["onlineMode"];
	        this.serverDir = source["serverDir"];
	    }
	}
	export class ServerStatus {
	    running: boolean;
	    name: string;
	    version: string;
	    port: number;
	    pid: number;
	    ready: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ServerStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.name = source["name"];
	        this.version = source["version"];
	        this.port = source["port"];
	        this.pid = source["pid"];
	        this.ready = source["ready"];
	    }
	}
	export class UserConfig {
	    versionIsolation: boolean;
	    selectedVersion: string;
	    themeColor: string;
	    backgroundImage: string;
	    showExportLaunchCommand: boolean;
	
	    static createFrom(source: any = {}) {
	        return new UserConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.versionIsolation = source["versionIsolation"];
	        this.selectedVersion = source["selectedVersion"];
	        this.themeColor = source["themeColor"];
	        this.backgroundImage = source["backgroundImage"];
	        this.showExportLaunchCommand = source["showExportLaunchCommand"];
	    }
	}
	export class UserInfo {
	    username: string;
	    hasPassword: boolean;
	    type: string;
	    isLocked: boolean;
	    serverName: string;
	
	    static createFrom(source: any = {}) {
	        return new UserInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.username = source["username"];
	        this.hasPassword = source["hasPassword"];
	        this.type = source["type"];
	        this.isLocked = source["isLocked"];
	        this.serverName = source["serverName"];
	    }
	}
	export class YggdrasilServerLinks {
	    homepage: string;
	    register: string;
	
	    static createFrom(source: any = {}) {
	        return new YggdrasilServerLinks(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.homepage = source["homepage"];
	        this.register = source["register"];
	    }
	}
	export class YggdrasilServerMeta {
	    serverName: string;
	
	    static createFrom(source: any = {}) {
	        return new YggdrasilServerMeta(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.serverName = source["serverName"];
	    }
	}
	export class YggdrasilServerInfo {
	    meta: YggdrasilServerMeta;
	    links: YggdrasilServerLinks;
	
	    static createFrom(source: any = {}) {
	        return new YggdrasilServerInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.meta = this.convertValues(source["meta"], YggdrasilServerMeta);
	        this.links = this.convertValues(source["links"], YggdrasilServerLinks);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	

}

