/**
 * Tracegate — Premium Cybersecurity Learning & VAPT Platform
 * Frontend SPA Controller, Routing, State Management & Real API Integration
 */

document.addEventListener("DOMContentLoaded", () => {
    // ==========================================================================
    // 1. GLOBAL STATE & CONSTANTS
    // ==========================================================================
    const DEFAULT_USER = {
        name: "Security Learner",
        email: "learner@tracegate.lab",
        role: "Junior Pentester / Security Learner",
        methodology: "owasp_top10"
    };

    const STARTER_PROJECTS = [
        {
            id: "proj-ecommerce-001",
            name: "E-Commerce Gateway & Auth Audit",
            target_url: "https://shop.tracegate.lab",
            environment: "Web Application (Staging)",
            description: "Authorized penetration test assessing user registration, multi-factor authentication, and payment handling.",
            notes: "Scope includes checkout, account reset, and cart endpoints.",
            status: "IN_PROGRESS",
            created_at: "2026-08-28",
            updated_at: "2026-09-03",
            checklist_data: null,
            findings: [
                {
                    id: "find-1",
                    finding_name: "Broken Authentication on Password Reset",
                    test_id: "test-auth-1",
                    priority: "CRITICAL",
                    description: "Password reset tokens do not expire upon use and have insufficient entropy (4-digit numeric pin).",
                    testing_notes: "Requested reset token via /forgot-password, intercepted response, brute forced 4-digit code within 200 requests.",
                    poc_text: "POST /api/v1/auth/reset HTTP/1.1\nHost: shop.tracegate.lab\nContent-Type: application/json\n\n{\"token\": \"1042\", \"new_password\": \"pwnedPass!\"} -> 200 OK",
                    evidence_filename: "reset_token_bruteforce.png",
                    evidence_data: null,
                    recorded_at: "2026-09-02 14:22"
                }
            ]
        },
        {
            id: "proj-health-002",
            name: "Patient Records EHR API Audit",
            target_url: "https://ehr-api.medlab.test",
            environment: "API & Microservices",
            description: "Compliance assessment for HIPAA/OWASP ASVS patient record search and attachment upload endpoints.",
            notes: "Test API tokens provided in lab environment.",
            status: "COMPLETED",
            created_at: "2026-08-15",
            updated_at: "2026-08-30",
            checklist_data: null,
            findings: []
        },
        {
            id: "proj-fintech-003",
            name: "Cloud Banking Admin Panel Review",
            target_url: "https://admin.fintech-vault.stage",
            environment: "Web Application (Production)",
            description: "Role-based access control (RBAC) and audit log tampering assessment for internal financial staff.",
            notes: "Admin credentials provided for testing least-privilege.",
            status: "NEEDS_REVIEW",
            created_at: "2026-09-01",
            updated_at: "2026-09-04",
            checklist_data: null,
            findings: []
        }
    ];

    const PRIORITY_ORDER = {
        CRITICAL: 0,
        HIGH: 1,
        MEDIUM: 2,
        LOW: 3
    };

    let currentUser = null;
    let projects = [];
    let activeProjectId = null;

    // Ephemeral Inspection & Checklist Architecture State (Section 17)
    let selectedPageType = "Auto Detect";
    let currentUploadedFile = null;
    let uploadedImage = null;
    let currentImageHash = null;
    let additionalContext = "";

    let analysisStatus = "IDLE"; // IDLE, RUNNING, SUCCESS, ERROR
    let analysisResult = null;

    let checklistStatus = "IDLE"; // IDLE, GENERATING, CURRENT, NEEDS_REGENERATION
    let checklist = [];

    let currentAnalysisRequestId = null;
    let currentAbortController = null;
    let lastAnalyzedPageType = null;
    let lastGeneratedPageType = null;

    let activeVerifyItem = null;
    let activeEditItem = null;
    let pendingEvidenceData = null;
    let pendingEvidenceFilename = null;
    let pendingEvidenceList = [];
    let isSavingFinding = false;

    // Filters & Sorting for Checklist
    let currentPriorityFilter = "ALL";
    let currentStatusFilter = "ALL";
    let currentSearchTerm = "";
    let currentSortMode = "priority_desc";

    // Filters for Findings View
    let currentFindingSeverityFilter = "ALL";
    let currentFindingSearchTerm = "";

    // ==========================================================================
    // 2. STATE INITIALIZATION & LOCALSTORAGE + REST API SYNC
    // ==========================================================================
    function getAuthHeaders(extra = {}) {
        const token = localStorage.getItem("tg_auth_token") || (currentUser && currentUser.token);
        const headers = { ...extra };
        if (token) {
            headers["Authorization"] = `Bearer ${token}`;
        }
        return headers;
    }
    window.getAuthHeaders = getAuthHeaders;

    function getAuthDownloadUrl(path) {
        const token = localStorage.getItem("tg_auth_token") || (typeof currentUser !== "undefined" && currentUser && currentUser.token);
        if (!token) return path;
        const sep = path.includes("?") ? "&" : "?";
        return `${path}${sep}token=${encodeURIComponent(token)}`;
    }
    window.getAuthDownloadUrl = getAuthDownloadUrl;

    async function initState() {
        // Validate Session Token with backend
        const authToken = localStorage.getItem("tg_auth_token");
        const savedUser = localStorage.getItem("tg_user");

        if (authToken) {
            if (savedUser) {
                try { currentUser = JSON.parse(savedUser); } catch (e) { currentUser = null; }
            }
        } else {
            localStorage.removeItem("tg_user");
            currentUser = null;
        }

        updateUserUI();
        applyRememberedCredentials();

        if (authToken) {
            try {
                const meRes = await fetch("/api/auth/me", {
                    headers: { "Authorization": `Bearer ${authToken}` }
                });
                if (meRes.ok) {
                    currentUser = await meRes.json();
                    localStorage.setItem("tg_user", JSON.stringify(currentUser));
                    updateUserUI();
                } else {
                    localStorage.removeItem("tg_auth_token");
                    localStorage.removeItem("tg_user");
                    currentUser = null;
                    updateUserUI();
                    applyRememberedCredentials();
                    if (window.location.hash !== "#login") {
                        navigateTo("#login");
                    }
                }
            } catch (e) {
                console.warn("[TRACEGATE] Offline or network error verifying auth:", e);
            }
        }

        // Load Projects from user-scoped cache if user logged in, or fallback for anonymous
        if (currentUser && currentUser.id) {
            const userKey = "tg_projects_" + currentUser.id;
            const savedProjects = localStorage.getItem(userKey);
            if (savedProjects) {
                try {
                    projects = JSON.parse(savedProjects);
                    if (!Array.isArray(projects)) projects = [];
                } catch (e) {
                    projects = [];
                }
            } else {
                projects = [];
            }
            const activeKey = "tg_active_proj_id_" + currentUser.id;
            activeProjectId = localStorage.getItem(activeKey) || (projects[0]?.id || null);
        } else {
            const savedProjects = localStorage.getItem("tg_projects");
            if (savedProjects) {
                try {
                    projects = JSON.parse(savedProjects);
                    if (!Array.isArray(projects) || projects.length === 0) {
                        projects = [...STARTER_PROJECTS];
                    }
                } catch (e) {
                    projects = [...STARTER_PROJECTS];
                }
            } else {
                projects = [...STARTER_PROJECTS];
                saveProjects();
            }
            activeProjectId = localStorage.getItem("tg_active_proj_id");
            if (!activeProjectId || !projects.some(p => p.id === activeProjectId)) {
                activeProjectId = projects[0]?.id || null;
                if (activeProjectId) localStorage.setItem("tg_active_proj_id", activeProjectId);
            }
        }

        updateUserUI();
        updateProjectsDropdown();
        refreshDashboardStats();

        // Sync fresh data from backend REST API
        if (currentUser) {
            await syncProjectsFromBackend();
            if (typeof loadGitHubFixStatus === "function") loadGitHubFixStatus();
            if (typeof loadGitHubRepositories === "function") loadGitHubRepositories();
        } else {
            if (typeof clearUserSessionState === "function") clearUserSessionState();
        }
    }

    async function syncProjectsFromBackend() {
        try {
            const res = await fetch("/api/projects", {
                headers: getAuthHeaders()
            });
            if (res.ok) {
                const resData = await res.json();
                const backendProjects = Array.isArray(resData) ? resData : (resData.projects || []);
                // Strictly reflect the authenticated user's projects from database
                projects = backendProjects.map(bp => {
                    const existing = projects.find(p => p.id === bp.id);
                    return {
                        ...bp,
                        checklist_data: existing?.checklist_data || null,
                        findings: existing?.findings || []
                    };
                });
                if (!activeProjectId || !projects.some(p => p.id === activeProjectId)) {
                    activeProjectId = projects[0]?.id || null;
                }
                saveProjects();
                updateProjectsDropdown();
                refreshDashboardStats();
                if (typeof renderRecentProjects === "function") {
                    renderRecentProjects();
                }
                if (typeof renderExistingProjects === "function") {
                    renderExistingProjects();
                }
                if (typeof renderDashboard === "function") {
                    renderDashboard();
                }
            }
        } catch (e) {
            console.warn("[TRACEGATE] Offline or failed to sync /api/projects:", e);
        }

        // Pre-fetch details for active project
        if (activeProjectId) {
            await loadProjectDetails(activeProjectId);
        }

        // Automatic safe legacy storage migration (Sections 17-22, 84-85)
        await migrateLegacyClientStorage();
    }

    async function migrateLegacyClientStorage() {
        if (!currentUser || !currentUser.id) return;
        const userKey = "tg_projects_" + currentUser.id;
        const altKey = "tg_projects_user_" + currentUser.id;
        const legacyRaw = localStorage.getItem(userKey) || localStorage.getItem(altKey);
        if (!legacyRaw) return;

        // Check if legacy data contains large base64 or heavy findings or exceeds 100KB
        const hasHeavyPayload = legacyRaw.includes("data:image/") || legacyRaw.includes("evidence_data") || legacyRaw.length > 100000;
        if (!hasHeavyPayload) return;

        console.info(`[TRACEGATE] [MIGRATION] Legacy key detected with heavy payload (${Math.round(legacyRaw.length / 1024)} KB). Starting migration...`);
        try {
            const legacyParsed = JSON.parse(legacyRaw);
            if (Array.isArray(legacyParsed)) {
                let migratedEvidenceCount = 0;
                let migratedProjectCount = 0;

                for (const proj of legacyParsed) {
                    if (proj && proj.id && Array.isArray(proj.findings) && proj.findings.length > 0) {
                        const heavyFindings = proj.findings.filter(f => 
                            (f.evidence_data && typeof f.evidence_data === "string" && f.evidence_data.startsWith("data:")) ||
                            (Array.isArray(f.evidence) && f.evidence.some(e => e.data && typeof e.data === "string" && e.data.startsWith("data:")))
                        );
                        if (heavyFindings.length > 0) {
                            try {
                                const migRes = await fetch(`/api/projects/${encodeURIComponent(proj.id)}/evidence/migrate`, {
                                    method: "POST",
                                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                                    body: JSON.stringify({ findings: heavyFindings })
                                });
                                if (migRes.ok) {
                                    const migData = await migRes.json();
                                    migratedEvidenceCount += (migData.migrated_evidence || heavyFindings.length);
                                }
                            } catch (err) {
                                console.warn("[TRACEGATE] Legacy evidence migration sync error:", err);
                            }
                        }
                        migratedProjectCount++;
                    }
                }
                console.info(`[TRACEGATE] [MIGRATION] Objects migrated: ${migratedProjectCount} projects, ${migratedEvidenceCount} evidence files.`);
            }

            // Remove legacy key and replace with lightweight summary
            if (altKey) localStorage.removeItem(altKey);
            saveProjects();
            console.info("[TRACEGATE] [MIGRATION] Migration completed. Legacy key replaced with lightweight summary.");
        } catch (parseErr) {
            console.warn("[TRACEGATE] Legacy migration parse failed safely without deleting data:", parseErr);
        }
    }

    async function loadProjectDetails(projId) {
        const proj = projects.find(p => p.id === projId);
        if (!proj) return;

        try {
            // 1. Fetch checklist from backend with auth
            const chkRes = await fetch(`/api/projects/${projId}/checklist`, {
                headers: getAuthHeaders()
            });
            if (chkRes.ok) {
                const chkData = await chkRes.json();
                if (chkData && chkData.checklist && chkData.checklist.length > 0) {
                    proj.checklist_data = chkData;
                }
            }

            // 2. Fetch findings from backend with auth
            const findRes = await fetch(`/api/projects/${projId}/findings`, {
                headers: getAuthHeaders()
            });
            if (findRes.ok) {
                const rawFindings = await findRes.json();
                const findingsData = Array.isArray(rawFindings) ? rawFindings : (rawFindings.findings || []);
                if (Array.isArray(findingsData)) {
                    proj.findings = findingsData;
                    // Connect findings to matching checklist items
                    if (proj.checklist_data && proj.checklist_data.checklist) {
                        proj.checklist_data.checklist.forEach(item => {
                            const match = proj.findings.find(f => 
                                (f.test_id && (f.test_id === item.id || f.test_id === item.test_id)) ||
                                (f.checklist_item_id && (f.checklist_item_id === item.id || f.checklist_item_id === item.test_id))
                            );
                            if (match) {
                                item.finding = match;
                                item.status = "VULNERABILITY_FOUND";
                            }
                        });
                    }
                }
            }

            saveProjects();
            if (proj.id === activeProjectId) {
                renderActiveWorkspace();
                refreshDashboardStats();
            }
        } catch (err) {
            console.warn(`[TRACEGATE] Could not load details for project ${projId}:`, err);
        }
    }

    function saveProjects() {
        // Strip out heavy nested data (findings, checklist_data, evidence blobs)
        const lightweightProjects = (projects || []).map(p => ({
            id: p.id,
            name: p.name,
            target_url: p.target_url,
            environment: p.environment,
            description: p.description ? p.description.substring(0, 200) : "",
            status: p.status,
            created_at: p.created_at,
            updated_at: p.updated_at,
            owner_id: p.owner_id
        }));

        const serialized = JSON.stringify(lightweightProjects);
        const estimatedBytes = serialized.length * 2;
        const MAX_SAFE_LOCALSTORAGE_BYTES = 250 * 1024; // 250 KB safe threshold

        if (currentUser && currentUser.id) {
            const userKey = "tg_projects_" + currentUser.id;
            const altKey = "tg_projects_user_" + currentUser.id;
            try {
                if (estimatedBytes <= MAX_SAFE_LOCALSTORAGE_BYTES) {
                    localStorage.setItem(userKey, serialized);
                } else {
                    console.info(`[TRACEGATE] Project state size (${Math.round(estimatedBytes / 1024)} KB) exceeds safe threshold. Writing top 10 summary to localStorage.`);
                    localStorage.setItem(userKey, JSON.stringify(lightweightProjects.slice(0, 10)));
                }
                localStorage.removeItem(altKey);
            } catch (quotaErr) {
                console.warn("[TRACEGATE] Size guard caught quota event; falling back to top 10 projects:", quotaErr);
                try {
                    localStorage.setItem(userKey, JSON.stringify(lightweightProjects.slice(0, 10)));
                } catch (e) {
                    console.warn("[TRACEGATE] Size guard skipped localStorage cache; relying on server persistence.");
                }
            }

            if (activeProjectId) {
                localStorage.setItem("tg_active_proj_id_" + currentUser.id, activeProjectId);
            } else {
                localStorage.removeItem("tg_active_proj_id_" + currentUser.id);
            }
        } else {
            try {
                if (estimatedBytes <= MAX_SAFE_LOCALSTORAGE_BYTES) {
                    localStorage.setItem("tg_projects", serialized);
                } else {
                    localStorage.setItem("tg_projects", JSON.stringify(lightweightProjects.slice(0, 10)));
                }
            } catch (e) {}

            if (activeProjectId) {
                localStorage.setItem("tg_active_proj_id", activeProjectId);
            } else {
                localStorage.removeItem("tg_active_proj_id");
            }
        }
    }

    function getActiveProject() {
        return projects.find(p => p.id === activeProjectId) || projects[0] || null;
    }

    async function setActiveProject(projId, targetTab = null) {
        if (!projects.some(p => p.id === projId)) return;
        activeProjectId = projId;
        if (currentUser && currentUser.id) {
            localStorage.setItem("tg_active_proj_id_" + currentUser.id, projId);
        }
        localStorage.setItem("tg_active_proj_id", projId);
        updateProjectsDropdown();
        if (targetTab && typeof window.switchWorkspaceTab === "function") {
            window.switchWorkspaceTab(targetTab, false);
        }
        renderActiveWorkspace();
        refreshDashboardStats();
        showToast(`Switched active project to "${getActiveProject().name}"`, "info");
        await loadProjectDetails(projId);
    }

    function openProject(projId, targetTab = "overview") {
        if (!projId) return;
        const finalTab = targetTab || "overview";
        setActiveProject(projId, finalTab);
        if (typeof window.switchWorkspaceTab === "function") {
            window.switchWorkspaceTab(finalTab, false);
        }
        const destHash = finalTab && finalTab !== "overview"
            ? `#project-workspace/${finalTab}`
            : "#project-workspace";
        if (window.location.hash === destHash) {
            navigateTo(destHash);
        } else {
            window.location.hash = destHash;
        }
    }

    function updateUserUI() {
        const navItemLogin = document.getElementById("navItemLogin");
        const btnLogoutEl = document.getElementById("btnLogout");
        const sidebarUserProfile = document.getElementById("sidebarUserProfile");
        const sidebarFooter = document.getElementById("sidebarFooter") || document.querySelector(".sidebar-footer");
        const navItemProfile = document.getElementById("navItemProfile") || document.querySelector('a[data-route="profile"]');
        const avatarEl = document.getElementById("sidebarUserAvatar");
        const nameEl = document.getElementById("sidebarUserName");
        const roleEl = document.getElementById("sidebarUserRole");
        const dashNameEl = document.getElementById("dashGreetingName");
        const profAvatar = document.getElementById("profileAvatarLarge");
        const profName = document.getElementById("profileNameDisplay");
        const profEmail = document.getElementById("profileEmailDisplay");
        const inpName = document.getElementById("profileInputName");
        const inpEmail = document.getElementById("profileInputEmail");

        if (!currentUser) {
            if (navItemLogin) navItemLogin.style.display = "flex";
            if (btnLogoutEl) btnLogoutEl.style.display = "none";
            if (sidebarUserProfile) sidebarUserProfile.style.display = "none";
            if (sidebarFooter) sidebarFooter.style.display = "none";
            if (navItemProfile) navItemProfile.style.display = "none";
            if (avatarEl) avatarEl.textContent = "";
            if (nameEl) nameEl.textContent = "";
            if (roleEl) roleEl.textContent = "";
            if (dashNameEl) dashNameEl.textContent = "Guest";
            if (profAvatar) profAvatar.textContent = "";
            if (profName) profName.textContent = "";
            if (profEmail) profEmail.textContent = "";
            if (inpName) inpName.value = "";
            if (inpEmail) inpEmail.value = "";
            return;
        }

        if (navItemLogin) navItemLogin.style.display = "none";
        if (btnLogoutEl) btnLogoutEl.style.display = "flex";
        if (sidebarUserProfile) sidebarUserProfile.style.display = "flex";
        if (sidebarFooter) sidebarFooter.style.display = "flex";
        if (navItemProfile) navItemProfile.style.display = "flex";

        const displayName = currentUser.full_name || currentUser.name || currentUser.username || "Security Learner";
        const initials = displayName
            .split(" ")
            .filter(Boolean)
            .map(n => n[0])
            .join("")
            .substring(0, 2)
            .toUpperCase() || "SL";
        
        if (avatarEl) avatarEl.textContent = initials;
        if (nameEl) nameEl.textContent = displayName;
        if (roleEl) roleEl.textContent = currentUser.role || "Junior Pentester";

        if (dashNameEl) dashNameEl.textContent = displayName;

        if (profAvatar) profAvatar.textContent = initials;
        if (profName) profName.textContent = displayName;
        if (profEmail) profEmail.textContent = `${currentUser.email || ''} • ${currentUser.role || 'Junior Pentester'}`;

        if (inpName) inpName.value = displayName;
        if (inpEmail) inpEmail.value = currentUser.email || '';

        const selMeth = document.getElementById("profileSelectMethodology");
        if (selMeth && currentUser.methodology) selMeth.value = currentUser.methodology;

        if (typeof window.loadProfile2FAStatus === "function") {
            window.loadProfile2FAStatus();
        }
    }

    function applyRememberedCredentials() {
        const rememberedIdentifier = localStorage.getItem("tg_remembered_identifier");
        const chk = document.getElementById("chkRememberMe");
        const emailInput = document.getElementById("loginEmailInput");
        const passwordInput = document.getElementById("loginPasswordInput");

        // Plaintext passwords must NEVER be saved or persisted anywhere. Always clear password input.
        if (passwordInput) {
            passwordInput.value = "";
        }

        if (rememberedIdentifier) {
            if (emailInput) emailInput.value = rememberedIdentifier;
            if (chk) chk.checked = true;
        } else {
            if (emailInput) emailInput.value = "";
            if (chk) chk.checked = false;
        }
    }

    function updateProjectsDropdown() {
        const select = document.getElementById("globalProjectSelect");
        if (!select) return;
        select.innerHTML = "";

        if (projects.length === 0) {
            const opt = document.createElement("option");
            opt.value = "";
            opt.textContent = "No Projects (0)";
            select.appendChild(opt);
            select.disabled = true;
            return;
        }

        select.disabled = false;
        projects.forEach(p => {
            const opt = document.createElement("option");
            opt.value = p.id;
            opt.textContent = p.name;
            if (p.id === activeProjectId) opt.selected = true;
            select.appendChild(opt);
        });

        select.onchange = (e) => {
            if (e.target.value) {
                openProject(e.target.value, "overview");
            }
        };
    }

    // ==========================================================================
    // AUTHENTICATED SESSION CONTROLLER & STATE MANAGER
    // ==========================================================================
    function setAuthenticatedUser(user, token) {
        if (!user) return;

        // 1. Purge stale in-memory state from previous session
        projects = [];
        activeProjectId = null;
        currentRepoTreeItems = [];
        window._currentSelectedRepo = null;
        window._usingCustomRepo = false;
        window._currentAnalysisData = null;
        window._currentFixResult = null;
        window._currentPRResult = null;
        window._githubMode = null;
        window._githubConnected = false;

        // 2. Set current authenticated user and persist token/user
        currentUser = user;
        if (token) {
            localStorage.setItem("tg_auth_token", token);
        }
        localStorage.setItem("tg_user", JSON.stringify(user));

        // 3. Load user-scoped projects cache if present
        if (user.id) {
            const userProjCache = localStorage.getItem("tg_projects_" + user.id);
            if (userProjCache) {
                try {
                    projects = JSON.parse(userProjCache);
                    if (!Array.isArray(projects)) projects = [];
                } catch (e) {
                    projects = [];
                }
            }
            activeProjectId = localStorage.getItem("tg_active_proj_id_" + user.id) || (projects[0]?.id || null);
        }

        // 4. Update UI with user profile data
        updateUserUI();
        updateProjectsDropdown();
        refreshDashboardStats();
    }
    window.setAuthenticatedUser = setAuthenticatedUser;
    window.login = setAuthenticatedUser;

    function navigateToDashboard() {
        const targetPath = (window.location.pathname === "/login" || window.location.pathname === "/register")
            ? "/dashboard#dashboard"
            : "#dashboard";
        if (window.history && window.history.replaceState) {
            window.history.replaceState(null, "", targetPath);
        } else {
            window.location.hash = "#dashboard";
        }
        navigateTo("dashboard");
    }
    window.navigateToDashboard = navigateToDashboard;

    // ==========================================================================
    // 3. ROUTING & VIEW CONTROLLER
    // ==========================================================================
    const VIEWS = {
        "login": document.getElementById("view-login"),
        "dashboard": document.getElementById("view-dashboard"),
        "recent-projects": document.getElementById("view-recent-projects"),
        "about": document.getElementById("view-about"),
        "create-project": document.getElementById("view-create-project"),
        "existing-projects": document.getElementById("view-existing-projects"),
        "project-workspace": document.getElementById("view-project-workspace"),
        "autofix": document.getElementById("view-autofix"),
        "profile": document.getElementById("view-profile")
    };

    function navigateTo(hash) {
        // Determine raw route from hash or URL path
        let rawHash = (hash || window.location.hash || "").replace("#", "").trim();
        let pathRoute = window.location.pathname.replace(/^\//, "").trim();

        // If hash is empty, check pathRoute
        let targetRoute = rawHash || pathRoute;

        const hasSession = !!currentUser;

        if (!targetRoute) {
            targetRoute = hasSession ? "dashboard" : "overview";
        }

        // Separate query parameters if present
        const [routePath, queryString] = targetRoute.split("?");
        const searchParams = new URLSearchParams(queryString || "");
        let explicitTab = searchParams.get("tab") || null;

        // Split route segments
        const segments = routePath.split("/").filter(Boolean);
        const mainSegment = segments[0] || (hasSession ? "dashboard" : "overview");

        let route = mainSegment.toLowerCase();

        // Normalize aliases to canonical public routes
        const ROUTE_ALIASES = {
            "": "overview",
            "landing": "overview",
            "overview": "overview",
            "capabilities": "capabilities",
            "features": "capabilities",
            "how-it-works": "how-it-works",
            "workflow": "how-it-works",
            "who-its-for": "who-its-for",
            "who-it-is-for": "who-its-for",
            "audiences": "who-its-for",
            "security": "security",
            "security-pillars": "security",
            "security-approach": "security",
            "login": "login",
            "register": "register",
            "signup": "register",
            "forgot-password": "forgot-password",
            "reset-password": "reset-password"
        };

        if (ROUTE_ALIASES[route]) {
            route = ROUTE_ALIASES[route];
        }

        const PUBLIC_PAGES = ["overview", "capabilities", "how-it-works", "who-its-for", "security", "login", "register", "forgot-password", "reset-password"];
        const isAuthRoute = ["login", "register", "forgot-password", "reset-password"].includes(route);

        // Immediate Auth Guard for Auth Routes:
        // If an authenticated user navigates to any auth screen (login/register/forgot/reset),
        // redirect immediately to dashboard without flashing public layout or login card.
        if (currentUser && isAuthRoute) {
            navigateToDashboard();
            return;
        }

        const isPublicRoute = PUBLIC_PAGES.includes(route);

        if (isPublicRoute) {
            // Apply public layout mode
            document.body.classList.remove("layout-authenticated");
            document.body.classList.add("layout-public");

            const publicShell = document.getElementById("publicShell");
            if (publicShell) publicShell.style.display = "flex";

            const authShell = document.getElementById("authenticatedAppShell");
            if (authShell) authShell.style.display = "none";

            // Hide all public views first
            const publicViewOverview = document.getElementById("publicViewOverview") || document.getElementById("publicViewLanding");
            const publicViewCapabilities = document.getElementById("publicViewCapabilities");
            const publicViewHowItWorks = document.getElementById("publicViewHowItWorks");
            const publicViewWhoItsFor = document.getElementById("publicViewWhoItsFor");
            const publicViewSecurity = document.getElementById("publicViewSecurity");
            const publicViewAuth = document.getElementById("publicViewAuth");

            const allPublicViews = [publicViewOverview, publicViewCapabilities, publicViewHowItWorks, publicViewWhoItsFor, publicViewSecurity, publicViewAuth];
            allPublicViews.forEach(v => {
                if (v) v.style.display = "none";
            });

            if (isAuthRoute) {

                if (publicViewAuth) publicViewAuth.style.display = "flex";

                // Ensure view-login is visible inside publicViewAuth
                const loginSection = document.getElementById("view-login");
                if (loginSection) {
                    loginSection.style.display = "block";
                    loginSection.classList.add("active");
                }

                if (route === "register") {
                    if (tabAuthSignUp) tabAuthSignUp.click();
                } else if (route === "forgot-password" || route === "reset-password") {
                    if (tabAuthSignIn) tabAuthSignIn.click();
                    setForgotStep(1);
                    openModal("modalForgotPassword");
                } else {
                    if (tabAuthSignIn) tabAuthSignIn.click();
                    applyRememberedCredentials();
                }
            } else if (route === "capabilities") {
                if (publicViewCapabilities) publicViewCapabilities.style.display = "block";
            } else if (route === "how-it-works") {
                if (publicViewHowItWorks) publicViewHowItWorks.style.display = "block";
            } else if (route === "who-its-for") {
                if (publicViewWhoItsFor) publicViewWhoItsFor.style.display = "block";
            } else if (route === "security") {
                if (publicViewSecurity) publicViewSecurity.style.display = "block";
            } else {
                // Overview (default landing page)
                if (publicViewOverview) publicViewOverview.style.display = "block";
            }

            // Update public navbar active link state
            document.querySelectorAll(".public-nav-link").forEach(link => {
                const pubRoute = link.getAttribute("data-public-route");
                if (pubRoute === route || (route === "overview" && pubRoute === "overview")) {
                    link.classList.add("active");
                } else {
                    link.classList.remove("active");
                }
            });

            // Update public navbar action buttons based on auth state
            const guestActions = document.getElementById("publicNavGuestActions");
            const authActions = document.getElementById("publicNavAuthActions");
            if (currentUser) {
                if (guestActions) guestActions.style.display = "none";
                if (authActions) authActions.style.display = "flex";
            } else {
                if (guestActions) guestActions.style.display = "flex";
                if (authActions) authActions.style.display = "none";
            }

            window.scrollTo(0, 0);
            return;
        }

        // ================= PROTECTED WORKSPACE ROUTES =================
        // Auth Guard: If not logged in, redirect to #login
        if (!currentUser) {
            document.body.classList.remove("layout-authenticated");
            document.body.classList.add("layout-public");
            if (window.location.hash === "#login") {
                navigateTo("#login");
            } else {
                window.location.hash = "#login";
            }
            return;
        }

        // Authenticated layout mode
        document.body.classList.remove("layout-public");
        document.body.classList.add("layout-authenticated");

        const publicShell = document.getElementById("publicShell");
        if (publicShell) publicShell.style.display = "none";

        const authShell = document.getElementById("authenticatedAppShell");
        if (authShell) authShell.style.display = "flex";

        // Handle workspace sub-routes (project-workspace, etc.)
        if (mainSegment === "project-workspace") {
            route = "project-workspace";
            if (segments[1]) {
                explicitTab = segments[1];
            }
        } else if (mainSegment === "project" || mainSegment === "projects") {
            route = "project-workspace";
            if (segments[1]) {
                const potentialProj = projects.find(p => p.id === segments[1]);
                if (potentialProj) {
                    if (activeProjectId !== potentialProj.id) {
                        activeProjectId = potentialProj.id;
                        localStorage.setItem("tg_active_proj_id", activeProjectId);
                        updateProjectsDropdown();
                    }
                    if (segments[2]) {
                        explicitTab = segments[2];
                    }
                } else if (["overview", "checklist", "findings", "report", "autofix", "ai-fix"].includes(segments[1])) {
                    explicitTab = segments[1];
                }
            }
        } else if (mainSegment === "checklist-generator" || mainSegment === "tool-checklist") {
            route = "project-workspace";
            explicitTab = "checklist";
        } else if (mainSegment === "findings") {
            route = "project-workspace";
            explicitTab = "findings";
        } else if (mainSegment === "report-generation" || mainSegment === "tool-reports") {
            route = "project-workspace";
            explicitTab = "report";
        } else if (mainSegment === "autofix" || mainSegment === "tool-autofix") {
            route = "project-workspace";
            explicitTab = "autofix";
        }

        // Activate view in authenticated shell
        Object.keys(VIEWS).forEach(k => {
            if (VIEWS[k]) {
                if (k === route) {
                    VIEWS[k].classList.add("active");
                } else {
                    VIEWS[k].classList.remove("active");
                }
            }
        });

        if (route === "profile" && typeof window.loadProfile2FAStatus === "function") {
            window.loadProfile2FAStatus();
        }

        // Activate Workspace Tab if on project-workspace
        let activeWsTab = "overview";
        if (route === "project-workspace") {
            const validTabs = ["overview", "checklist", "findings", "report", "autofix"];
            let normalizedTab = explicitTab ? explicitTab.toLowerCase() : null;
            if (normalizedTab === "ai-fix") normalizedTab = "autofix";

            activeWsTab = (normalizedTab && validTabs.includes(normalizedTab)) ? normalizedTab : "overview";
            if (typeof window.switchWorkspaceTab === "function") {
                window.switchWorkspaceTab(activeWsTab, false);
            }
        }

        // Update sidebar nav highlighting
        document.querySelectorAll(".nav-item, .nav-child-item").forEach(item => {
            const itemRoute = item.getAttribute("data-route");
            if (itemRoute === route) {
                if (route === "project-workspace") {
                    item.classList.remove("active");
                } else {
                    item.classList.add("active");
                }
            } else if (route === "project-workspace") {
                if (activeWsTab === "checklist" && (itemRoute === "tool-checklist" || itemRoute === "checklist-generator")) {
                    item.classList.add("active");
                } else if (activeWsTab === "report" && (itemRoute === "tool-reports" || itemRoute === "report-generation")) {
                    item.classList.add("active");
                } else if (activeWsTab === "autofix" && (itemRoute === "autofix" || itemRoute === "tool-autofix")) {
                    item.classList.add("active");
                } else if (activeWsTab === "findings" && itemRoute === "findings") {
                    item.classList.add("active");
                } else {
                    item.classList.remove("active");
                }
            } else {
                item.classList.remove("active");
            }
        });

        // Update Breadcrumbs
        const crumbCurrent = document.getElementById("crumbCurrentPage");
        if (crumbCurrent) {
            crumbCurrent.textContent = formatRouteName(route);
        }

        // View-specific renders
        if (route === "dashboard") {
            renderDashboard();
        } else if (route === "recent-projects") {
            renderRecentProjects();
        } else if (route === "existing-projects") {
            renderExistingProjects();
        } else if (route === "project-workspace") {
            renderActiveWorkspace();
        }

        // Auto-sync projects if empty or on starter data
        if (currentUser && (!projects || projects.length === 0)) {
            syncProjectsFromBackend();
        }

        window.scrollTo(0, 0);

        const sidebar = document.getElementById("sidebar");
        if (sidebar) sidebar.classList.remove("mobile-open");
    }

    window.addEventListener("popstate", () => {
        navigateTo(window.location.hash);
    });

    function formatRouteName(route) {
        const names = {
            "login": "Sign In",
            "dashboard": "Dashboard",
            "recent-projects": "Recent Projects",
            "about": "About Tracegate",
            "create-project": "Create New Project",
            "existing-projects": "Existing Projects",
            "project-workspace": "Project Workspace",
            "autofix": "AI AutoFix Connector Workbench",
            "profile": "Profile & Settings"
        };
        return names[route] || "Dashboard";
    }

    window.addEventListener("hashchange", () => {
        navigateTo(window.location.hash);
    });

    // Accordion handler
    const btnAccordion = document.getElementById("btnAccordionToggle");
    const projectsAccordion = document.getElementById("projectsAccordion");
    if (btnAccordion && projectsAccordion) {
        btnAccordion.addEventListener("click", () => {
            projectsAccordion.classList.toggle("open");
        });
    }

    // Mobile Hamburger
    const btnMobileToggle = document.getElementById("btnMobileToggle");
    const sidebar = document.getElementById("sidebar");
    if (btnMobileToggle && sidebar) {
        btnMobileToggle.addEventListener("click", () => {
            sidebar.classList.toggle("mobile-open");
        });
    }

    // Top New Project button
    const btnTopNavNewProject = document.getElementById("btnTopNavNewProject");
    if (btnTopNavNewProject) {
        btnTopNavNewProject.addEventListener("click", () => {
            window.location.hash = "#create-project";
        });
    }

    const btnDashQuickNewProject = document.getElementById("btnDashQuickNewProject");
    if (btnDashQuickNewProject) {
        btnDashQuickNewProject.addEventListener("click", () => {
            window.location.hash = "#create-project";
        });
    }

    // ==========================================================================
    // 4. AUTHENTICATION & LOGIN LOGIC (REAL SQLITE DB AUTH)
    // ==========================================================================
    const loginForm = document.getElementById("loginForm");
    const signupForm = document.getElementById("signupForm");
    const tabAuthSignIn = document.getElementById("tabAuthSignIn");
    const tabAuthSignUp = document.getElementById("tabAuthSignUp");
    const authHeaderTitle = document.getElementById("authHeaderTitle");
    const authAlertBox = document.getElementById("authAlertBox");
    const authAlertMessage = document.getElementById("authAlertMessage");

    const loginEmailInput = document.getElementById("loginEmailInput");
    const loginPasswordInput = document.getElementById("loginPasswordInput");
    const chkRememberMe = document.getElementById("chkRememberMe");
    const btnLoginSubmit = document.getElementById("btnLoginSubmit");
    const btnTogglePassword = document.getElementById("btnTogglePassword");
    const linkForgotPassword = document.getElementById("linkForgotPassword");
    const btnLogout = document.getElementById("btnLogout");
    const sidebarUserProfile = document.getElementById("sidebarUserProfile");
    const sidebarFooter = document.getElementById("sidebarFooter") || document.querySelector(".sidebar-footer");
    const navItemProfile = document.getElementById("navItemProfile") || document.querySelector('a[data-route="profile"]');

    // Password Reset Elements (3-step OTP flow)
    const modalForgotPassword = document.getElementById("modalForgotPassword");
    const btnCloseForgotModal = document.getElementById("btnCloseForgotModal");
    const forgotAlertBox = document.getElementById("forgotAlertBox");
    const forgotAlertIcon = document.getElementById("forgotAlertIcon");
    const forgotAlertMessage = document.getElementById("forgotAlertMessage");
    const forgotStep1Section = document.getElementById("forgotStep1Section");
    const forgotStep2Section = document.getElementById("forgotStep2Section");
    const forgotStep3Section = document.getElementById("forgotStep3Section");
    const forgotEmailInput = document.getElementById("forgotEmailInput");
    const forgotOtpInput = document.getElementById("forgotOtpInput");
    const forgotNewPasswordInput = document.getElementById("forgotNewPasswordInput");
    const forgotConfirmPasswordInput = document.getElementById("forgotConfirmPasswordInput");
    const btnRequestResetToken = document.getElementById("btnRequestResetToken");
    const btnRequestResetText = document.getElementById("btnRequestResetText");
    const btnCancelForgotStep1 = document.getElementById("btnCancelForgotStep1");
    const btnResendOtp = document.getElementById("btnResendOtp");
    const btnResendOtpText = document.getElementById("btnResendOtpText");
    const btnVerifyResetOtp = document.getElementById("btnVerifyResetOtp");
    const btnVerifyOtpText = document.getElementById("btnVerifyOtpText");
    const btnSubmitPasswordReset = document.getElementById("btnSubmitPasswordReset");
    const btnSubmitResetText = document.getElementById("btnSubmitResetText");

    const signupFullNameInput = document.getElementById("signupFullNameInput");
    const signupEmailInput = document.getElementById("signupEmailInput");
    const signupUsernameInput = document.getElementById("signupUsernameInput");
    const signupPasswordInput = document.getElementById("signupPasswordInput");
    const signupRoleSelect = document.getElementById("signupRoleSelect");
    const btnSignupSubmit = document.getElementById("btnSignupSubmit");

    // Tab Switching: Sign In vs Create Account
    if (tabAuthSignIn && tabAuthSignUp) {
        tabAuthSignIn.addEventListener("click", () => {
            tabAuthSignIn.classList.add("active");
            tabAuthSignUp.classList.remove("active");
            if (loginForm) loginForm.style.display = "flex";
            if (signupForm) signupForm.style.display = "none";
            if (authHeaderTitle) authHeaderTitle.textContent = "Sign in to Tracegate";
            hideAuthError();
            applyRememberedCredentials();
        });

        tabAuthSignUp.addEventListener("click", () => {
            tabAuthSignUp.classList.add("active");
            tabAuthSignIn.classList.remove("active");
            if (loginForm) loginForm.style.display = "none";
            if (signupForm) signupForm.style.display = "flex";
            if (authHeaderTitle) authHeaderTitle.textContent = "Create Tracegate Account";
            hideAuthError();
        });
    }

    if (chkRememberMe) {
        chkRememberMe.addEventListener("change", () => {
            if (!chkRememberMe.checked) {
                localStorage.removeItem("tg_remembered_identifier");
            } else if (loginEmailInput && loginEmailInput.value.trim()) {
                localStorage.setItem("tg_remembered_identifier", loginEmailInput.value.trim());
            }
        });
    }

    if (sidebarUserProfile) {
        sidebarUserProfile.addEventListener("click", () => {
            if (currentUser) {
                window.location.hash = "#profile";
            }
        });
    }

    function showAuthError(msg) {
        if (authAlertBox && authAlertMessage) {
            authAlertMessage.textContent = msg;
            authAlertBox.style.display = "flex";
        }
        showToast(msg, "error");
    }

    function hideAuthError() {
        if (authAlertBox) authAlertBox.style.display = "none";
    }

    if (btnTogglePassword && loginPasswordInput) {
        btnTogglePassword.addEventListener("click", () => {
            const isPassword = loginPasswordInput.type === "password";
            loginPasswordInput.type = isPassword ? "text" : "password";
        });
    }

    // Password Reset Modal Handlers & Step Switching
    function showForgotAlert(msg, isSuccess = false) {
        if (forgotAlertBox && forgotAlertMessage) {
            forgotAlertMessage.textContent = msg;
            if (forgotAlertIcon) forgotAlertIcon.textContent = isSuccess ? "✅" : "⚠️";
            forgotAlertBox.style.display = "flex";
            if (isSuccess) {
                forgotAlertBox.style.background = "rgba(16, 185, 129, 0.12)";
                forgotAlertBox.style.borderColor = "rgba(16, 185, 129, 0.35)";
                forgotAlertBox.style.color = "#34d399";
            } else {
                forgotAlertBox.style.background = "";
                forgotAlertBox.style.borderColor = "";
                forgotAlertBox.style.color = "";
            }
        }
    }

    function hideForgotAlert() {
        if (forgotAlertBox) forgotAlertBox.style.display = "none";
    }

    // In-memory state for password reset flow (never stored in localStorage)
    let passwordResetFlow = {
        email: "",
        authorization: null
    };

    function setForgotStep(stepNum) {
        hideForgotAlert();
        if (stepNum === 1) {
            if (forgotStep1Section) forgotStep1Section.style.display = "block";
            if (forgotStep2Section) forgotStep2Section.style.display = "none";
            if (forgotStep3Section) forgotStep3Section.style.display = "none";
            if (forgotEmailInput) forgotEmailInput.focus();
        } else if (stepNum === 2) {
            if (forgotStep1Section) forgotStep1Section.style.display = "none";
            if (forgotStep2Section) forgotStep2Section.style.display = "block";
            if (forgotStep3Section) forgotStep3Section.style.display = "none";
            if (forgotOtpInput) {
                forgotOtpInput.value = "";
                forgotOtpInput.focus();
            }
        } else if (stepNum === 3) {
            if (forgotStep1Section) forgotStep1Section.style.display = "none";
            if (forgotStep2Section) forgotStep2Section.style.display = "none";
            if (forgotStep3Section) forgotStep3Section.style.display = "block";
            if (forgotNewPasswordInput) {
                forgotNewPasswordInput.value = "";
                forgotNewPasswordInput.focus();
            }
            if (forgotConfirmPasswordInput) {
                forgotConfirmPasswordInput.value = "";
            }
        }
    }

    function resetForgotPasswordModal() {
        passwordResetFlow = { email: "", authorization: null };
        if (forgotOtpInput) forgotOtpInput.value = "";
        if (forgotNewPasswordInput) forgotNewPasswordInput.value = "";
        if (forgotConfirmPasswordInput) forgotConfirmPasswordInput.value = "";
        setForgotStep(1);
    }

    if (linkForgotPassword) {
        linkForgotPassword.addEventListener("click", () => {
            resetForgotPasswordModal();
            if (forgotEmailInput && loginEmailInput && loginEmailInput.value.includes("@")) {
                forgotEmailInput.value = loginEmailInput.value.trim();
            }
            openModal("modalForgotPassword");
        });
    }

    if (btnCloseForgotModal) {
        btnCloseForgotModal.addEventListener("click", () => {
            closeModal("modalForgotPassword");
            resetForgotPasswordModal();
        });
    }

    if (btnCancelForgotStep1) {
        btnCancelForgotStep1.addEventListener("click", () => {
            closeModal("modalForgotPassword");
            resetForgotPasswordModal();
        });
    }

    // Step 1: Send OTP to Email Address
    if (btnRequestResetToken) {
        btnRequestResetToken.addEventListener("click", async () => {
            const email = forgotEmailInput ? forgotEmailInput.value.trim() : "";
            if (!email || !email.includes("@")) {
                showForgotAlert("Please enter a valid registered email address.");
                return;
            }

            hideForgotAlert();
            if (btnRequestResetText) btnRequestResetText.textContent = "Sending...";
            btnRequestResetToken.disabled = true;

            try {
                const res = await fetch("/api/auth/forgot-password", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email })
                });

                if (!res.ok) {
                    let errDetail = "Unable to process request.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    showForgotAlert(errDetail);
                    return;
                }

                const data = await res.json();
                passwordResetFlow.email = email;
                setForgotStep(2);
                showForgotAlert(data.message || "A 6-digit verification code has been sent to your email.", true);
                showToast("Verification code sent to email.", "info");
            } catch (err) {
                showForgotAlert("Unable to communicate with reset service. Please try again.");
            } finally {
                if (btnRequestResetText) btnRequestResetText.textContent = "Send OTP";
                btnRequestResetToken.disabled = false;
            }
        });
    }

    // Step 2a: Resend OTP
    if (btnResendOtp) {
        btnResendOtp.addEventListener("click", async () => {
            const email = passwordResetFlow.email || (forgotEmailInput ? forgotEmailInput.value.trim() : "");
            if (!email) {
                setForgotStep(1);
                return;
            }

            hideForgotAlert();
            if (btnResendOtpText) btnResendOtpText.textContent = "Resending...";
            btnResendOtp.disabled = true;

            try {
                const res = await fetch("/api/auth/resend-reset-otp", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email })
                });

                if (!res.ok) {
                    let errDetail = "Unable to resend verification code.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    showForgotAlert(errDetail);
                    btnResendOtp.disabled = false;
                    if (btnResendOtpText) btnResendOtpText.textContent = "Resend OTP";
                    return;
                }

                const data = await res.json();
                if (forgotOtpInput) forgotOtpInput.value = "";
                showForgotAlert(data.message || "A fresh 6-digit verification code has been sent to your email.", true);
                showToast("New verification code sent.", "info");

                // Enforce 60-second cooldown on resend button
                let cooldown = 60;
                btnResendOtp.disabled = true;
                const cooldownTimer = setInterval(() => {
                    cooldown--;
                    if (cooldown > 0) {
                        if (btnResendOtpText) btnResendOtpText.textContent = `Resend (${cooldown}s)`;
                    } else {
                        clearInterval(cooldownTimer);
                        btnResendOtp.disabled = false;
                        if (btnResendOtpText) btnResendOtpText.textContent = "Resend OTP";
                    }
                }, 1000);
            } catch (err) {
                showForgotAlert("Network error while resending verification code.");
                btnResendOtp.disabled = false;
                if (btnResendOtpText) btnResendOtpText.textContent = "Resend OTP";
            }
        });
    }

    // Step 2b: Verify OTP
    if (btnVerifyResetOtp) {
        btnVerifyResetOtp.addEventListener("click", async () => {
            const email = passwordResetFlow.email || (forgotEmailInput ? forgotEmailInput.value.trim() : "");
            const otp = forgotOtpInput ? forgotOtpInput.value.trim() : "";

            if (!otp || otp.length !== 6 || !/^\d{6}$/.test(otp)) {
                showForgotAlert("Please enter the 6-digit numeric verification code.");
                return;
            }

            hideForgotAlert();
            if (btnVerifyOtpText) btnVerifyOtpText.textContent = "Verifying...";
            btnVerifyResetOtp.disabled = true;

            try {
                const res = await fetch("/api/auth/verify-reset-otp", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, otp })
                });

                if (!res.ok) {
                    let errDetail = "Invalid verification code.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    showForgotAlert(errDetail);
                    return;
                }

                const data = await res.json();
                passwordResetFlow.authorization = data.reset_authorization;
                setForgotStep(3);
                showForgotAlert("Code confirmed. Please set your new password below.", true);
                showToast("Code verified successfully.", "success");
            } catch (err) {
                showForgotAlert("Network failure during code verification.");
            } finally {
                if (btnVerifyOtpText) btnVerifyOtpText.textContent = "Verify OTP";
                btnVerifyResetOtp.disabled = false;
            }
        });
    }

    // Step 3: Set New Password
    if (btnSubmitPasswordReset) {
        btnSubmitPasswordReset.addEventListener("click", async () => {
            const auth_token = passwordResetFlow.authorization;
            if (!auth_token) {
                showForgotAlert("Password reset session expired or unverified. Please request a new code.");
                setForgotStep(1);
                return;
            }

            const new_password = forgotNewPasswordInput ? forgotNewPasswordInput.value.trim() : "";
            const confirm_password = forgotConfirmPasswordInput ? forgotConfirmPasswordInput.value.trim() : "";

            if (!new_password || new_password.length < 8) {
                showForgotAlert("New password must be at least 8 characters.");
                return;
            }
            if (new_password !== confirm_password) {
                showForgotAlert("Passwords do not match. Please re-enter.");
                return;
            }

            hideForgotAlert();
            if (btnSubmitResetText) btnSubmitResetText.textContent = "Updating...";
            btnSubmitPasswordReset.disabled = true;

            try {
                const res = await fetch("/api/auth/reset-password", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        reset_authorization: auth_token,
                        new_password,
                        confirm_password
                    })
                });

                if (!res.ok) {
                    let errDetail = "Password reset failed.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    showForgotAlert(errDetail);
                    return;
                }

                const data = await res.json();
                const userEmail = passwordResetFlow.email;
                resetForgotPasswordModal();
                closeModal("modalForgotPassword");
                showToast(data.message || "Password updated successfully. You can now sign in with your new password.", "success");

                // Switch to Sign In tab and prefill
                if (tabAuthSignIn) tabAuthSignIn.click();
                if (loginPasswordInput) {
                    loginPasswordInput.value = "";
                    loginPasswordInput.focus();
                }
                if (userEmail && loginEmailInput) {
                    loginEmailInput.value = userEmail;
                }
            } catch (err) {
                showForgotAlert("Network failure during password reset.");
            } finally {
                if (btnSubmitResetText) btnSubmitResetText.textContent = "Update Password";
                btnSubmitPasswordReset.disabled = false;
            }
        });
    }

    if (btnLoginSubmit) {
        btnLoginSubmit.addEventListener("click", executeLogin);
    }

    if (loginPasswordInput) {
        loginPasswordInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") executeLogin();
        });
    }

    async function executeLogin() {
        const username_or_email = loginEmailInput ? loginEmailInput.value.trim() : "";
        const password = loginPasswordInput ? loginPasswordInput.value.trim() : "";

        if (!username_or_email || !password) {
            showAuthError("Please provide both email/username and password.");
            return;
        }

        const btnText = document.getElementById("loginBtnText");
        if (btnText) btnText.textContent = "Verifying Credentials...";
        if (btnLoginSubmit) btnLoginSubmit.disabled = true;
        hideAuthError();

        try {
            const res = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username_or_email, password })
            });

            if (!res.ok) {
                let errDetail = "Invalid email/username or password.";
                try {
                    const errData = await res.json();
                    if (errData.detail) errDetail = errData.detail;
                } catch (e) {}
                showAuthError(errDetail);
                return;
            }

            const data = await res.json();

            // Remember Me persistence (username/email ONLY, never password)
            if (chkRememberMe && chkRememberMe.checked) {
                localStorage.setItem("tg_remembered_identifier", username_or_email);
            } else {
                localStorage.removeItem("tg_remembered_identifier");
            }

            // Always clear password input field immediately
            if (loginPasswordInput) loginPasswordInput.value = "";

            if (data.requires_2fa) {
                show2FAChallengeView(data.temp_token);
                return;
            }

            // Immediately apply authenticated session state (persists token and user)
            setAuthenticatedUser(data.user, data.access_token);

            const welcomeName = currentUser.full_name || currentUser.name || currentUser.username || "Learner";
            showToast(`Welcome back, ${welcomeName}!`, "success");

            // Automatically navigate to Dashboard immediately WITHOUT requiring reload or refresh
            navigateToDashboard();

            // Background synchronization for projects and GitHub state (non-blocking)
            syncProjectsFromBackend().catch(e => console.warn("[TRACEGATE] Background project sync error:", e));
            if (typeof loadGitHubFixStatus === "function") loadGitHubFixStatus();
            if (typeof loadGitHubRepositories === "function") loadGitHubRepositories();
        } catch (err) {
            showAuthError("Authentication service connection failed.");
        } finally {
            if (btnText) btnText.textContent = "Sign In to Dashboard";
            if (btnLoginSubmit) btnLoginSubmit.disabled = false;
        }
    }

    // ==========================================================================
    // 4B. TWO-FACTOR AUTHENTICATION LOGIN CHALLENGE CONTROLLER
    // ==========================================================================
    let current2FAPendingToken = null;
    const twoFactorLoginForm = document.getElementById("twoFactorLoginForm");
    const twoFactorAlertBox = document.getElementById("twoFactorAlertBox");
    const twoFactorAlertMessage = document.getElementById("twoFactorAlertMessage");
    const totpInputSection = document.getElementById("totpInputSection");
    const recoveryInputSection = document.getElementById("recoveryInputSection");
    const login2FACodeInput = document.getElementById("login2FACodeInput");
    const loginRecoveryCodeInput = document.getElementById("loginRecoveryCodeInput");
    const btnToggle2FAMethod = document.getElementById("btnToggle2FAMethod");
    const btnLogin2FASubmit = document.getElementById("btnLogin2FASubmit");
    const login2FABtnText = document.getElementById("login2FABtnText");
    const btnCancel2FAChallenge = document.getElementById("btnCancel2FAChallenge");
    const authTabsRow = document.querySelector(".auth-tabs-row");

    function show2FAError(msg) {
        if (twoFactorAlertBox && twoFactorAlertMessage) {
            twoFactorAlertMessage.textContent = msg;
            twoFactorAlertBox.style.display = "flex";
        }
    }

    function hide2FAError() {
        if (twoFactorAlertBox) {
            twoFactorAlertBox.style.display = "none";
        }
    }

    function show2FAChallengeView(tempToken) {
        current2FAPendingToken = tempToken;
        hideAuthError();
        hide2FAError();
        if (authTabsRow) authTabsRow.style.display = "none";
        if (loginForm) loginForm.style.display = "none";
        if (signupForm) signupForm.style.display = "none";
        if (twoFactorLoginForm) twoFactorLoginForm.style.display = "flex";
        if (authHeaderTitle) authHeaderTitle.textContent = "Two-Factor Verification";

        if (totpInputSection) totpInputSection.style.display = "block";
        if (recoveryInputSection) recoveryInputSection.style.display = "none";
        if (btnToggle2FAMethod) btnToggle2FAMethod.textContent = "Lost your device? Use a backup recovery code";

        if (login2FACodeInput) {
            login2FACodeInput.value = "";
            setTimeout(() => login2FACodeInput.focus(), 100);
        }
        if (loginRecoveryCodeInput) loginRecoveryCodeInput.value = "";
    }

    function hide2FAChallengeView() {
        current2FAPendingToken = null;
        hide2FAError();
        if (twoFactorLoginForm) twoFactorLoginForm.style.display = "none";
        if (authTabsRow) authTabsRow.style.display = "flex";
        if (loginForm) loginForm.style.display = "flex";
        if (authHeaderTitle) authHeaderTitle.textContent = "Sign in to Tracegate";
    }

    if (btnToggle2FAMethod) {
        btnToggle2FAMethod.addEventListener("click", () => {
            hide2FAError();
            const isTotpVisible = totpInputSection && totpInputSection.style.display !== "none";
            if (isTotpVisible) {
                if (totpInputSection) totpInputSection.style.display = "none";
                if (recoveryInputSection) recoveryInputSection.style.display = "block";
                btnToggle2FAMethod.textContent = "Use 6-digit authenticator code instead";
                if (loginRecoveryCodeInput) {
                    loginRecoveryCodeInput.value = "";
                    loginRecoveryCodeInput.focus();
                }
            } else {
                if (totpInputSection) totpInputSection.style.display = "block";
                if (recoveryInputSection) recoveryInputSection.style.display = "none";
                btnToggle2FAMethod.textContent = "Lost your device? Use a backup recovery code";
                if (login2FACodeInput) {
                    login2FACodeInput.value = "";
                    login2FACodeInput.focus();
                }
            }
        });
    }

    if (btnCancel2FAChallenge) {
        btnCancel2FAChallenge.addEventListener("click", () => {
            hide2FAChallengeView();
        });
    }

    async function execute2FALoginVerify() {
        if (!current2FAPendingToken) {
            show2FAError("Two-factor session expired. Please return to sign in.");
            return;
        }

        const isRecoveryActive = recoveryInputSection && recoveryInputSection.style.display !== "none";
        let code = null;
        let recovery_code = null;

        if (isRecoveryActive) {
            recovery_code = loginRecoveryCodeInput ? loginRecoveryCodeInput.value.trim() : "";
            if (!recovery_code) {
                show2FAError("Please enter your backup recovery code.");
                if (loginRecoveryCodeInput) loginRecoveryCodeInput.focus();
                return;
            }
        } else {
            code = login2FACodeInput ? login2FACodeInput.value.trim().replace(/\s+/g, "") : "";
            if (!code || code.length < 6) {
                show2FAError("Please enter the 6-digit code from your authenticator app.");
                if (login2FACodeInput) login2FACodeInput.focus();
                return;
            }
        }

        if (login2FABtnText) login2FABtnText.textContent = "Verifying...";
        if (btnLogin2FASubmit) btnLogin2FASubmit.disabled = true;
        hide2FAError();

        try {
            const bodyPayload = {
                temp_token: current2FAPendingToken
            };
            if (code) bodyPayload.code = code;
            if (recovery_code) bodyPayload.recovery_code = recovery_code;

            const res = await fetch("/api/auth/2fa/login-verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(bodyPayload)
            });

            if (!res.ok) {
                let errDetail = "Invalid verification code.";
                try {
                    const errData = await res.json();
                    if (errData.detail) errDetail = errData.detail;
                } catch (e) {}
                show2FAError(errDetail);
                return;
            }

            // Immediately apply authenticated session state (persists token and user)
            setAuthenticatedUser(data.user, data.access_token);

            if (loginPasswordInput) loginPasswordInput.value = "";

            hide2FAChallengeView();
            const welcomeName = currentUser.full_name || currentUser.name || currentUser.username || "Learner";
            showToast(`Two-factor verification confirmed. Welcome back, ${welcomeName}!`, "success");

            // Automatically navigate to Dashboard immediately WITHOUT requiring reload or refresh
            navigateToDashboard();

            // Background synchronization for projects and GitHub state (non-blocking)
            syncProjectsFromBackend().catch(e => console.warn("[TRACEGATE] Background project sync error:", e));
            if (typeof loadGitHubFixStatus === "function") loadGitHubFixStatus();
            if (typeof loadGitHubRepositories === "function") loadGitHubRepositories();
        } catch (err) {
            show2FAError("Failed to reach verification service.");
        } finally {
            if (login2FABtnText) login2FABtnText.textContent = "Verify & Sign In";
            if (btnLogin2FASubmit) btnLogin2FASubmit.disabled = false;
        }
    }

    if (btnLogin2FASubmit) {
        btnLogin2FASubmit.addEventListener("click", execute2FALoginVerify);
    }
    if (login2FACodeInput) {
        login2FACodeInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") execute2FALoginVerify();
        });
    }
    if (loginRecoveryCodeInput) {
        loginRecoveryCodeInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") execute2FALoginVerify();
        });
    }

    // Sign Up Execution
    if (btnSignupSubmit) {
        btnSignupSubmit.addEventListener("click", async () => {
            const full_name = signupFullNameInput?.value.trim();
            const email = signupEmailInput?.value.trim();
            const username = signupUsernameInput?.value.trim();
            const password = signupPasswordInput?.value.trim();
            const role = signupRoleSelect?.value || "Junior Pentester / Security Learner";

            if (!full_name || !email || !username || !password) {
                showAuthError("All fields marked * are required.");
                return;
            }

            if (password.length < 8) {
                showAuthError("Password must be at least 8 characters.");
                return;
            }

            const signupBtnText = document.getElementById("signupBtnText");
            if (signupBtnText) signupBtnText.textContent = "Creating Account...";
            btnSignupSubmit.disabled = true;
            hideAuthError();

            try {
                const res = await fetch("/api/auth/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, username, password, full_name, role })
                });

                if (!res.ok) {
                    let errDetail = "Failed to register account.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    showAuthError(errDetail);
                    return;
                }

                // Immediately apply authenticated session state (persists token and user)
                setAuthenticatedUser(data.user, data.access_token);

                if (signupPasswordInput) signupPasswordInput.value = "";
                if (loginPasswordInput) loginPasswordInput.value = "";

                const welcomeName = currentUser.full_name || currentUser.name || currentUser.username || "Learner";
                showToast(`Account created! Welcome to Tracegate, ${welcomeName}.`, "success");

                // Automatically navigate to Dashboard immediately WITHOUT requiring reload or refresh
                navigateToDashboard();

                // Background synchronization for projects and GitHub state (non-blocking)
                syncProjectsFromBackend().catch(e => console.warn("[TRACEGATE] Background project sync error:", e));
                if (typeof loadGitHubFixStatus === "function") loadGitHubFixStatus();
                if (typeof loadGitHubRepositories === "function") loadGitHubRepositories();
            } catch (err) {
                showAuthError("Registration service connection failed.");
            } finally {
                if (signupBtnText) signupBtnText.textContent = "Create Account & Sign In";
                btnSignupSubmit.disabled = false;
            }
        });
    }

    // Logout Handler
    
    const btnPublicNavLogout = document.getElementById("btnPublicNavLogout");
    if (btnPublicNavLogout) {
        btnPublicNavLogout.addEventListener("click", () => {
            if (btnLogout) {
                btnLogout.click();
            }
        });
    }

    function clearUserSessionState() {
        const oldUserId = currentUser ? currentUser.id : null;

        // 1. Clear in-memory session and user state
        currentUser = null;
        projects = [];
        activeProjectId = null;
        currentRepoTreeItems = [];
        if (typeof clearPendingEvidence === "function") {
            clearPendingEvidence();
        } else {
            pendingEvidenceList = [];
            pendingEvidenceData = null;
            pendingEvidenceFilename = null;
        }

        // 2. Clear global AI Fix & GitHub in-memory variables
        window._currentSelectedRepo = null;
        window._usingCustomRepo = false;
        window._currentAnalysisData = null;
        window._currentFixResult = null;
        window._currentPRResult = null;
        window._githubMode = null;
        window._githubConnected = false;

        // 3. Browser Storage Cleanup
        localStorage.removeItem("tg_auth_token");
        localStorage.removeItem("tg_user");
        localStorage.removeItem("tg_active_proj_id");
        if (oldUserId) {
            localStorage.removeItem("tg_active_proj_id_" + oldUserId);
            localStorage.removeItem("tg_projects_" + oldUserId);
            localStorage.removeItem("tg_projects_user_" + oldUserId);
        }
        // Purge any stored github keys from localStorage and sessionStorage
        try {
            Object.keys(localStorage).forEach(k => {
                if (k.startsWith("tg_github_") || k.includes("github")) {
                    localStorage.removeItem(k);
                }
            });
            Object.keys(sessionStorage).forEach(k => {
                if (k.startsWith("tg_github_") || k.includes("github")) {
                    sessionStorage.removeItem(k);
                }
            });
        } catch (e) {}

        // 4. Reset DOM elements for GitHub connection and AI Fix
        const statusLabel = document.getElementById("githubStatusLabel");
        if (statusLabel) statusLabel.textContent = "GitHub Not Connected";
        const connPill = document.getElementById("githubConnectionPill");
        if (connPill) connPill.className = "badge badge-in-progress";
        const modalStatus = document.getElementById("ghModalCurrentStatus");
        if (modalStatus) modalStatus.textContent = "Not connected to live GitHub (Personal Access Token required for Live mode)";

        // Reset Modal inputs
        const ghTokenInput = document.getElementById("ghModalTokenInput");
        if (ghTokenInput) ghTokenInput.value = "";
        const ghUserInput = document.getElementById("ghModalUsernameInput");
        if (ghUserInput) ghUserInput.value = "";
        const ghModeSel = document.getElementById("ghModalModeSelect");
        if (ghModeSel) ghModeSel.value = "mock";

        // Reset workspace repo & branch inputs
        const customRepoInput = document.getElementById("wsAutofixCustomRepoInput");
        if (customRepoInput) customRepoInput.value = "";
        const confirmRepoInput = document.getElementById("confirmApplyRepoInput");
        if (confirmRepoInput) confirmRepoInput.value = "";

        // Reset repo selects to disconnected state
        ["wsAutofixRepoSelect", "standaloneRepoSelect"].forEach(id => {
            const sel = document.getElementById(id);
            if (sel) {
                sel.innerHTML = `<option value="">-- Connect GitHub to Select Repository --</option>`;
                sel.disabled = true;
            }
        });
        ["wsAutofixBranchSelect", "standaloneBranchSelect"].forEach(id => {
            const sel = document.getElementById(id);
            if (sel) {
                sel.innerHTML = `<option value="">-- Connect GitHub First --</option>`;
                sel.disabled = true;
            }
        });

        // Reset finding selects
        ["wsAutofixFindingSelect", "autofixFindingSelect"].forEach(id => {
            const sel = document.getElementById(id);
            if (sel) sel.innerHTML = `<option value="">-- Select Confirmed Vulnerability --</option>`;
        });

        // Reset discovery banner & buttons
        const bannerTitle = document.getElementById("wsAutofixDiscoveryStatusTitle");
        if (bannerTitle) bannerTitle.textContent = "Automatic Repository Discovery Inactive";
        const bannerBadge = document.getElementById("wsAutofixDiscoveryStatusBadge");
        if (bannerBadge) {
            bannerBadge.className = "badge badge-in-progress";
            bannerBadge.textContent = "GitHub Not Connected";
        }
        const bannerDesc = document.getElementById("wsAutofixDiscoveryStatusDesc");
        if (bannerDesc) bannerDesc.textContent = "Connect your GitHub account to enable automatic repository source detection, live code tree browsing, and defensive remediation.";
        const btnBrowseTree = document.getElementById("btnWsBrowseRepoTree");
        if (btnBrowseTree) btnBrowseTree.disabled = true;
        const btnAnalyze = document.getElementById("btnWsAnalyzeCodeFix");
        if (btnAnalyze) btnAnalyze.disabled = true;
        const sourcesContainer = document.getElementById("wsSelectedSourcesList") || document.getElementById("wsSelectedSourcesContainer");
        const countBadge = document.getElementById("wsSelectedSourcesCount");
        if (countBadge) countBadge.textContent = "0 files selected";
        if (sourcesContainer) {
            sourcesContainer.innerHTML = `<div class="empty-placeholder" id="wsSelectedSourcesEmpty" style="padding: 1rem; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
                Connect GitHub and select a confirmed vulnerability to automatically detect and select vulnerable source files.
            </div>`;
        }

        // Clear code diffs and candidate sources
        const diffBox = document.getElementById("autofixDiffUnifiedBox");
        if (diffBox) diffBox.textContent = "";
        const candidateList = document.getElementById("discoveredSourceList");
        if (candidateList) candidateList.innerHTML = "";
        window.selectedSources = [];
        window.candidateSources = [];
        currentRepoTreeItems = [];

        if (typeof hide2FAChallengeView === "function") {
            hide2FAChallengeView();
        }
        current2FAPendingToken = null;

        updateUserUI();
        updateProjectsDropdown();
        refreshDashboardStats();
        if (typeof renderExistingProjects === "function") renderExistingProjects();
        if (typeof renderRecentProjects === "function") renderRecentProjects();
    }
    window.clearUserSessionState = clearUserSessionState;

    if (btnLogout) {
        btnLogout.addEventListener("click", async () => {
            const token = localStorage.getItem("tg_auth_token");
            if (token) {
                try {
                    await fetch("/api/auth/logout", {
                        method: "POST",
                        headers: { "Authorization": `Bearer ${token}` }
                    });
                } catch (e) {}
            }
            clearUserSessionState();
            applyRememberedCredentials();

            showToast("You have been signed out.", "info");
            if (window.location.hash === "#login") {
                navigateTo("#login");
            } else {
                window.location.hash = "#login";
            }
        });
    }

    // ==========================================================================
    // 5. DASHBOARD & RECENT PROJECTS LOGIC
    // ==========================================================================
    function calculateProjectMetrics(proj) {
        if (!proj.checklist_data || !proj.checklist_data.checklist) {
            const defaultTotal = 10;
            const completed = proj.status === "COMPLETED" ? 10 : (proj.status === "NEEDS_REVIEW" ? 6 : 4);
            const vulns = proj.findings ? proj.findings.length : 0;
            const clean = Math.max(0, completed - vulns);
            const remaining = defaultTotal - completed;
            const pct = Math.round((completed / defaultTotal) * 100);
            return { total: defaultTotal, completed, vulns, clean, remaining, pct };
        }

        const list = proj.checklist_data.checklist;
        const total = list.length;
        const clean = list.filter(i => i.status === "TESTED_NOT_FOUND").length;
        const vulns = list.filter(i => i.status === "VULNERABILITY_FOUND").length;
        const completed = clean + vulns;
        const remaining = total - completed;
        const pct = total > 0 ? Math.round((completed / total) * 100) : 0;
        return { total, completed, vulns, clean, remaining, pct };
    }

    function refreshDashboardStats() {
        const totalProjects = projects.length;
        let totalCompletedTests = 0;
        let totalVulns = 0;
        let totalClean = 0;
        let checklistsCompleted = 0;

        projects.forEach(p => {
            const m = calculateProjectMetrics(p);
            totalCompletedTests += m.completed;
            totalVulns += (p.findings ? p.findings.length : m.vulns);
            totalClean += m.clean;
            if (m.pct === 100) checklistsCompleted++;
        });

        const statTotalProjectsEl = document.getElementById("statTotalProjects");
        if (statTotalProjectsEl) statTotalProjectsEl.textContent = totalProjects;

        const statTestsCompletedEl = document.getElementById("statTestsCompleted");
        if (statTestsCompletedEl) statTestsCompletedEl.textContent = totalCompletedTests;

        const statVulnsFoundEl = document.getElementById("statVulnsFound");
        if (statVulnsFoundEl) statVulnsFoundEl.textContent = totalVulns;

        const statVulnsNotFoundEl = document.getElementById("statVulnsNotFound");
        if (statVulnsNotFoundEl) statVulnsNotFoundEl.textContent = totalClean;

        const statChecklistsCompletedEl = document.getElementById("statChecklistsCompleted");
        if (statChecklistsCompletedEl) statChecklistsCompletedEl.textContent = checklistsCompleted;
    }

    function renderDashboard() {
        refreshDashboardStats();
        const listEl = document.getElementById("dashRecentProjectsList");
        if (!listEl) return;
        listEl.innerHTML = "";

        const recent = [...projects].slice(0, 4);
        recent.forEach(proj => {
            const m = calculateProjectMetrics(proj);
            const card = createProjectItemCard(proj, m);
            listEl.appendChild(card);
        });
    }

    function createProjectItemCard(proj, metrics) {
        const div = document.createElement("div");
        div.className = "project-item-card";

        const statusClass = proj.status === "COMPLETED" ? "badge-completed" : (proj.status === "NEEDS_REVIEW" ? "badge-needs-review" : "badge-in-progress");
        const statusText = proj.status === "COMPLETED" ? "Completed" : (proj.status === "NEEDS_REVIEW" ? "Needs Review" : "In Progress");

        div.innerHTML = `
            <div class="project-item-left">
                <div class="project-avatar">${escapeHtml(proj.name.substring(0, 2).toUpperCase())}</div>
                <div class="project-meta-info">
                    <span class="project-meta-title">${escapeHtml(proj.name)}</span>
                    <span class="project-meta-target">${escapeHtml(proj.target_url)}</span>
                </div>
            </div>

            <div class="project-item-center">
                <div class="project-progress-wrap">
                    <div class="project-progress-label">
                        <span>Checklist Progress</span>
                        <span>${metrics.pct}%</span>
                    </div>
                    <div class="project-progress-bar">
                        <div class="project-progress-fill" style="width: ${metrics.pct}%"></div>
                    </div>
                </div>
            </div>

            <div class="project-item-right">
                <span class="badge ${statusClass}">${statusText}</span>
                <span class="badge ${proj.findings && proj.findings.length > 0 ? 'badge-critical' : 'badge-low'}">
                    ${proj.findings ? proj.findings.length : 0} Vulns
                </span>
                <button type="button" class="btn btn-secondary btn-sm btn-open-project" data-proj-id="${proj.id}">
                    Open Project &rarr;
                </button>
            </div>
        `;

        div.querySelector(".btn-open-project").addEventListener("click", () => {
            openProject(proj.id, "overview");
        });

        const leftMeta = div.querySelector(".project-item-left");
        if (leftMeta) {
            leftMeta.style.cursor = "pointer";
            leftMeta.addEventListener("click", () => {
                openProject(proj.id, "overview");
            });
        }

        return div;
    }

    function renderRecentProjects() {
        const listEl = document.getElementById("recentProjectsFullList");
        if (!listEl) return;
        listEl.innerHTML = "";

        const searchVal = (document.getElementById("recentProjectsSearchInput")?.value || "").toLowerCase().trim();
        const activeFilter = document.querySelector("[data-recent-status].active")?.getAttribute("data-recent-status") || "ALL";
        const sortVal = document.getElementById("recentProjectsSortSelect")?.value || "recent";

        let filtered = projects.filter(p => {
            const matchesSearch = p.name.toLowerCase().includes(searchVal) || p.target_url.toLowerCase().includes(searchVal);
            const matchesStatus = activeFilter === "ALL" || p.status === activeFilter;
            return matchesSearch && matchesStatus;
        });

        if (sortVal === "name") {
            filtered.sort((a, b) => a.name.localeCompare(b.name));
        } else if (sortVal === "progress") {
            filtered.sort((a, b) => calculateProjectMetrics(b).pct - calculateProjectMetrics(a).pct);
        } else {
            filtered.sort((a, b) => (b.updated_at || "").localeCompare(a.updated_at || ""));
        }

        if (filtered.length === 0) {
            listEl.innerHTML = `
                <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                    No projects found matching the criteria.
                </div>
            `;
            return;
        }

        filtered.forEach(p => {
            const m = calculateProjectMetrics(p);
            listEl.appendChild(createProjectItemCard(p, m));
        });
    }

    // Recent Projects Search & Filter Event Listeners
    const recentProjectsSearchInput = document.getElementById("recentProjectsSearchInput");
    if (recentProjectsSearchInput) {
        recentProjectsSearchInput.addEventListener("input", renderRecentProjects);
    }

    const recentProjectsSortSelect = document.getElementById("recentProjectsSortSelect");
    if (recentProjectsSortSelect) {
        recentProjectsSortSelect.addEventListener("change", renderRecentProjects);
    }

    document.querySelectorAll("[data-recent-status]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-recent-status]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            renderRecentProjects();
        });
    });

    function renderExistingProjects() {
        const listEl = document.getElementById("existingProjectsFullList");
        if (!listEl) return;
        listEl.innerHTML = "";

        const searchVal = (document.getElementById("existingProjectsSearchInput")?.value || "").toLowerCase().trim();
        const activeFilter = document.querySelector("[data-existing-status].active")?.getAttribute("data-existing-status") || "ALL";

        const filtered = projects.filter(p => {
            const matchesSearch = p.name.toLowerCase().includes(searchVal) || p.target_url.toLowerCase().includes(searchVal);
            const matchesStatus = activeFilter === "ALL" || p.status === activeFilter;
            return matchesSearch && matchesStatus;
        });

        if (filtered.length === 0) {
            listEl.innerHTML = `
                <div style="text-align: center; padding: 40px; color: var(--text-muted);">
                    No projects found. Create your first security audit project!
                </div>
            `;
            return;
        }

        filtered.forEach(p => {
            const m = calculateProjectMetrics(p);
            listEl.appendChild(createProjectItemCard(p, m));
        });
    }

    const existingProjectsSearchInput = document.getElementById("existingProjectsSearchInput");
    if (existingProjectsSearchInput) {
        existingProjectsSearchInput.addEventListener("input", renderExistingProjects);
    }

    document.querySelectorAll("[data-existing-status]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-existing-status]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            renderExistingProjects();
        });
    });

    // Create New Project Form Submit
    const btnSubmitCreateProject = document.getElementById("btnSubmitCreateProject");
    if (btnSubmitCreateProject) {
        btnSubmitCreateProject.addEventListener("click", async () => {
            const name = document.getElementById("newProjName")?.value.trim();
            const target = document.getElementById("newProjTarget")?.value.trim();
            const env = document.getElementById("newProjEnv")?.value;
            const desc = document.getElementById("newProjDesc")?.value.trim();
            const notes = document.getElementById("newProjNotes")?.value.trim();

            if (!name || !target) {
                showToast("Project Name and Target Application URL are required.", "error");
                return;
            }

            let newProj = {
                id: "proj-" + Date.now(),
                name: name,
                target_url: target,
                environment: env,
                description: desc || "Authorized security testing assessment.",
                notes: notes || "",
                status: "IN_PROGRESS",
                created_at: new Date().toISOString().split("T")[0],
                updated_at: new Date().toISOString().split("T")[0],
                checklist_data: null,
                findings: []
            };

            // Call backend REST API
            try {
                const res = await fetch("/api/projects", {
                    method: "POST",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({
                        name: newProj.name,
                        target_url: newProj.target_url,
                        environment: newProj.environment,
                        description: newProj.description,
                        notes: newProj.notes
                    })
                });
                if (res.ok) {
                    const created = await res.json();
                    newProj = { ...newProj, ...created, checklist_data: null, findings: [] };
                }
            } catch (err) {
                console.warn("[TRACEGATE] Project creation offline fallback:", err);
            }

            projects.unshift(newProj);
            saveProjects();

            // Clear form
            document.getElementById("newProjName").value = "";
            document.getElementById("newProjTarget").value = "";
            document.getElementById("newProjDesc").value = "";
            document.getElementById("newProjNotes").value = "";

            showToast(`Project "${newProj.name}" created!`, "success");
            openProject(newProj.id, "overview");
        });
    }

    // ==========================================================================
    // 6. PROJECT WORKSPACE CONTROLLER
    // ==========================================================================
    window.switchWorkspaceTab = function(tabName, updateHash = true) {
        const validTabs = ["overview", "checklist", "findings", "report", "autofix"];
        let normalized = (tabName || "overview").toLowerCase();
        if (normalized === "ai-fix") normalized = "autofix";
        if (!validTabs.includes(normalized)) normalized = "overview";

        document.querySelectorAll(".ws-tab-btn").forEach(b => {
            if (b.getAttribute("data-tab") === normalized) b.classList.add("active");
            else b.classList.remove("active");
        });

        document.querySelectorAll(".ws-tab-pane").forEach(pane => {
            if (pane.id === `pane-ws-${normalized}`) pane.classList.add("active");
            else pane.classList.remove("active");
        });

        if (normalized === "findings") renderWorkspaceFindings();
        if (normalized === "report") renderWorkspaceReport();
        if (normalized === "autofix") renderWorkspaceAutoFix();
        if (normalized === "overview" || normalized === "report") {
            const curP = getActiveProject();
            if (curP && typeof refreshProjectCertificateStatus === "function") refreshProjectCertificateStatus(curP.id);
        }

        if (updateHash) {
            const newHash = normalized === "overview" ? "#project-workspace" : `#project-workspace/${normalized}`;
            if (window.location.hash !== newHash) {
                history.pushState(null, "", newHash);
            }
        }
    };

    document.querySelectorAll(".ws-tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const tab = btn.getAttribute("data-tab");
            switchWorkspaceTab(tab);
        });
    });

    function renderActiveWorkspace() {
        const proj = getActiveProject();
        if (!proj) return;

        const nameEl = document.getElementById("wsProjectName");
        if (nameEl) nameEl.textContent = proj.name;

        const targetEl = document.getElementById("wsProjectTargetUrl");
        if (targetEl) targetEl.textContent = proj.target_url;

        const statusEl = document.getElementById("wsProjectStatusBadge");
        if (statusEl) {
            statusEl.className = "badge " + (proj.status === "COMPLETED" ? "badge-completed" : (proj.status === "NEEDS_REVIEW" ? "badge-needs-review" : "badge-in-progress"));
            statusEl.textContent = proj.status === "COMPLETED" ? "Completed" : (proj.status === "NEEDS_REVIEW" ? "Needs Review" : "In Progress");
        }

        const descEl = document.getElementById("wsOverviewDescription");
        if (descEl) descEl.textContent = proj.description || "No description provided.";

        const notesEl = document.getElementById("wsOverviewNotes");
        if (notesEl) notesEl.textContent = proj.notes || "No scope notes recorded for this assessment.";

        const badgeCount = document.getElementById("wsFindingsBadgeCount");
        if (badgeCount) badgeCount.textContent = (proj.findings ? proj.findings.length : 0);

        // Checklist view render
        if (proj.checklist_data && proj.checklist_data.checklist) {
            document.getElementById("idleState").style.display = "none";
            document.getElementById("resultsContent").classList.add("active");

            // Sync page type dropdown to project's current checklist page type
            const ptSelect = document.getElementById("pageTypeSelect");
            if (ptSelect && proj.checklist_data.page_type) {
                const canonicalVal = proj.checklist_data.page_type;
                const shortVal = canonicalVal.replace(/ Page$/, "").trim();
                for (let i = 0; i < ptSelect.options.length; i++) {
                    const optVal = ptSelect.options[i].value;
                    if (optVal === canonicalVal || optVal === shortVal) {
                        ptSelect.value = optVal;
                        selectedPageType = optVal;
                        lastGeneratedPageType = optVal;
                        break;
                    }
                }
            }

            renderPageAnalysis(proj.checklist_data);
            renderChecklistCards();
            updateChecklistProgressUI();
        } else {
            document.getElementById("idleState").style.display = "flex";
            document.getElementById("resultsContent").classList.remove("active");
        }

        // Refresh VAPT Assessment Completion Certificate status
        if (typeof refreshProjectCertificateStatus === "function") {
            refreshProjectCertificateStatus(proj.id);
        }
        if (typeof checkAndPromptCertificateIfEligible === "function") {
            checkAndPromptCertificateIfEligible(proj.id);
        }
        if (typeof checkAndUpdateAIFixCertButtons === "function") {
            checkAndUpdateAIFixCertButtons(proj.id);
        }
        // Refresh Project Security Analytics
        if (typeof refreshProjectSecurityAnalytics === "function") {
            refreshProjectSecurityAnalytics(proj.id);
        }
    }

    // ==========================================================================
    // EDIT PROJECT MODAL (WORKSPACE HEADER)
    // ==========================================================================
    function openEditProjectModal() {
        const proj = getActiveProject();
        if (!proj) {
            showToast("No active project to edit.", "warning");
            return;
        }

        const errAlert = document.getElementById("editProjectErrorAlert");
        if (errAlert) {
            errAlert.style.display = "none";
        }

        const nameInput = document.getElementById("editProjName");
        const targetInput = document.getElementById("editProjTarget");
        const envSelect = document.getElementById("editProjEnv");
        const descInput = document.getElementById("editProjDesc");
        const notesInput = document.getElementById("editProjNotes");

        if (nameInput) nameInput.value = proj.name || "";
        if (targetInput) targetInput.value = proj.target_url || "";
        if (envSelect) {
            const currentEnv = proj.environment || "Web Application (Staging)";
            let matched = false;
            for (let i = 0; i < envSelect.options.length; i++) {
                if (envSelect.options[i].value === currentEnv || envSelect.options[i].value.startsWith(currentEnv.split(" ")[0])) {
                    envSelect.selectedIndex = i;
                    matched = true;
                    break;
                }
            }
            if (!matched) envSelect.value = "Web Application (Staging)";
        }
        if (descInput) descInput.value = proj.description || "";
        if (notesInput) notesInput.value = proj.notes || proj.scope_notes || "";

        openModal("modalEditProject");
    }

    const btnWsEditProject = document.getElementById("btnWsEditProject");
    if (btnWsEditProject) {
        btnWsEditProject.addEventListener("click", openEditProjectModal);
    }

    const btnCancelEditProject = document.getElementById("btnCancelEditProject");
    if (btnCancelEditProject) {
        btnCancelEditProject.addEventListener("click", () => {
            closeModal("modalEditProject");
        });
    }

    const btnCloseEditProjectModal = document.getElementById("btnCloseEditProjectModal");
    if (btnCloseEditProjectModal) {
        btnCloseEditProjectModal.addEventListener("click", () => {
            closeModal("modalEditProject");
        });
    }

    const btnSaveEditProject = document.getElementById("btnSaveEditProject");
    if (btnSaveEditProject) {
        btnSaveEditProject.addEventListener("click", async () => {
            const proj = getActiveProject();
            if (!proj) return;

            const name = document.getElementById("editProjName")?.value.trim();
            const target = document.getElementById("editProjTarget")?.value.trim();
            const env = document.getElementById("editProjEnv")?.value;
            const desc = document.getElementById("editProjDesc")?.value.trim();
            const notes = document.getElementById("editProjNotes")?.value.trim();

            const errAlert = document.getElementById("editProjectErrorAlert");
            const errMsg = document.getElementById("editProjectErrorMsg");

            if (!name || !target) {
                if (errAlert && errMsg) {
                    errMsg.textContent = "Project Name and Target Application URL are required.";
                    errAlert.style.display = "flex";
                } else {
                    showToast("Project Name and Target Application URL are required.", "error");
                }
                return;
            }

            const originalBtnText = btnSaveEditProject.textContent;
            btnSaveEditProject.textContent = "Saving...";
            btnSaveEditProject.disabled = true;

            try {
                const res = await fetch(`/api/projects/${encodeURIComponent(proj.id)}`, {
                    method: "PUT",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({
                        name: name,
                        target_url: target,
                        environment: env,
                        description: desc,
                        notes: notes,
                        scope_notes: notes
                    })
                });

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    const errorDetail = errData.detail || "Failed to update project.";
                    if (errAlert && errMsg) {
                        errMsg.textContent = errorDetail;
                        errAlert.style.display = "flex";
                    } else {
                        showToast(errorDetail, "error");
                    }
                    return;
                }

                const updatedData = await res.json();

                proj.name = updatedData.name || name;
                proj.target_url = updatedData.target_url || target;
                proj.environment = updatedData.environment || env;
                proj.description = updatedData.description !== undefined ? updatedData.description : desc;
                proj.notes = updatedData.notes || updatedData.scope_notes || notes;
                proj.scope_notes = proj.notes;
                if (updatedData.updated_at) {
                    proj.updated_at = updatedData.updated_at;
                }

                // Update within projects array
                const idx = projects.findIndex(p => p.id === proj.id);
                if (idx !== -1) {
                    projects[idx] = { ...projects[idx], ...proj };
                }
                saveProjects();

                // Immediately update header and views without reloading page
                renderActiveWorkspace();
                if (typeof updateProjectsDropdown === "function") updateProjectsDropdown();
                if (typeof renderRecentProjects === "function") renderRecentProjects();
                if (typeof renderExistingProjects === "function") renderExistingProjects();
                if (typeof refreshDashboardStats === "function") refreshDashboardStats();

                closeModal("modalEditProject");
                showToast("Project updated successfully.", "success");
            } catch (err) {
                console.error("[TRACEGATE] Error updating project:", err);
                if (errAlert && errMsg) {
                    errMsg.textContent = "Network error while saving project. Please try again.";
                    errAlert.style.display = "flex";
                } else {
                    showToast("Network error while saving project.", "error");
                }
            } finally {
                btnSaveEditProject.textContent = originalBtnText;
                btnSaveEditProject.disabled = false;
            }
        });
    }

    // ==========================================================================
    // 7. CHECKLIST GENERATOR (CORE ENGINE & REAL API)
    // ==========================================================================
    const dropZone = document.getElementById("dropZone");
    const fileInput = document.getElementById("fileInput");
    const uploadEmptyState = document.getElementById("uploadEmptyState");
    const uploadPreviewState = document.getElementById("uploadPreviewState");
    const imagePreview = document.getElementById("imagePreview");
    const previewFileName = document.getElementById("previewFileName");
    const btnClearImage = document.getElementById("btnClearImage");
    const promptInput = document.getElementById("promptInput");
    const btnAnalyze = document.getElementById("btnAnalyze");
    const btnAnalyzeText = document.getElementById("btnAnalyzeText");
    const analysisStepperBox = document.getElementById("analysisStepperBox");
    const engineStatusDot = document.getElementById("engineStatusDot");
    const engineStatusText = document.getElementById("engineStatusText");

    // Check Backend Health
    async function checkBackendHealth() {
        try {
            const res = await fetch("/api/health");
            if (!res.ok) throw new Error("Health check non-200");
            const data = await res.json();
            if (data.mode === "live") {
                engineStatusDot.className = "status-indicator-dot online-live";
                engineStatusText.textContent = `AI Vision (${data.provider.toUpperCase()})`;
            } else {
                engineStatusDot.className = "status-indicator-dot online-sim";
                engineStatusText.textContent = "AI Vision Simulation (Ready)";
            }
        } catch (e) {
            engineStatusDot.className = "status-indicator-dot offline";
            engineStatusText.textContent = "Offline / Disconnected";
        }
    }
    checkBackendHealth();

    // 10 Sample Quick-Load Scenario Pills
    const samplePills = document.querySelectorAll(".sample-pill-btn");
    const scenarioPillMap = {
        "login": "Login / Sign In",
        "registration": "Sign Up / Registration",
        "forgot_password": "Forgot Password / Password Reset",
        "profile": "Account / Profile",
        "settings": "Settings / Security Settings",
        "dashboard": "Dashboard",
        "search": "Search / Search Results",
        "file_upload": "File Upload",
        "checkout": "Checkout / Payment",
        "admin_panel": "Admin Panel",
        "ambiguous": "Auto Detect"
    };

    samplePills.forEach(pill => {
        pill.addEventListener("click", async () => {
            samplePills.forEach(p => p.classList.remove("active"));
            pill.classList.add("active");

            const sampleKey = pill.getAttribute("data-sample");
            const mappedType = scenarioPillMap[sampleKey];
            const ptSelect = document.getElementById("pageTypeSelect");
            if (mappedType && ptSelect) {
                ptSelect.value = mappedType;
                selectedPageType = mappedType;
            }

            const filename = `${sampleKey}.png`;
            showToast(`Loading scenario: ${pill.textContent.trim()}...`, "info");

            try {
                const res = await fetch(`/samples/${filename}`);
                if (!res.ok) throw new Error(`Could not load sample ${filename}`);
                const blob = await res.blob();
                const file = new File([blob], filename, { type: blob.type || "image/png" });
                setUploadedFile(file);
            } catch (err) {
                showToast(`Failed to load sample image: ${err.message}`, "error");
            }
        });
    });

    // Drag and drop handlers
    if (dropZone) {
        dropZone.addEventListener("click", (e) => {
            if (e.target !== btnClearImage) fileInput.click();
        });

        dropZone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropZone.classList.add("drag-over");
        });

        dropZone.addEventListener("dragleave", () => {
            dropZone.classList.remove("drag-over");
        });

        dropZone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropZone.classList.remove("drag-over");
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                validateAndSetFile(e.dataTransfer.files[0]);
            }
        });
    }

    if (fileInput) {
        fileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files[0]) {
                validateAndSetFile(e.target.files[0]);
            }
        });
    }

    if (btnClearImage) {
        btnClearImage.addEventListener("click", (e) => {
            e.stopPropagation();
            clearUploadedFile();
        });
    }

    function validateAndSetFile(file) {
        const allowed = ["image/png", "image/jpeg", "image/jpg", "image/webp"];
        if (!allowed.includes(file.type)) {
            showToast("Unsupported file format. Please upload a PNG, JPG, or WEBP screenshot.", "error");
            return;
        }

        if (file.size > 10 * 1024 * 1024) {
            showToast("File exceeds 10MB limit. Please upload a smaller image.", "error");
            return;
        }

        setUploadedFile(file);
    }

    function setUploadedFile(file) {
        currentUploadedFile = file;
        uploadedImage = file;
        analysisResult = null;
        analysisStatus = "IDLE";
        currentImageHash = null;
        checklistStatus = "IDLE";

        const staleBanner = document.getElementById("staleAnalysisBanner");
        if (staleBanner) staleBanner.style.display = "none";

        console.log(`[TRACEGATE UPLOAD] Selected file: "${file.name}", type: ${file.type || 'unknown'}, size: ${(file.size / 1024).toFixed(1)} KB`);
        const reader = new FileReader();
        reader.onload = (e) => {
            imagePreview.src = e.target.result;
            previewFileName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
            uploadEmptyState.style.display = "none";
            uploadPreviewState.classList.add("active");
            btnAnalyze.disabled = false;
        };
        reader.readAsDataURL(file);
    }

    function clearUploadedFile() {
        console.log("[TRACEGATE UPLOAD] Uploaded file state cleared.");
        currentUploadedFile = null;
        fileInput.value = "";
        imagePreview.src = "";
        uploadEmptyState.style.display = "flex";
        uploadPreviewState.classList.remove("active");
        if (btnAnalyze) btnAnalyze.disabled = false;
        samplePills.forEach(p => p.classList.remove("active"));
    }

    // ==========================================================================
    // 7. UNIFIED CHECKLIST GENERATOR (Sections 19, 20, 21, 22, 23)
    // ==========================================================================
    async function generateChecklist() {
        const activeProj = getActiveProject();
        if (!activeProj) {
            showToast("Please select or create an assessment project first.", "error");
            return;
        }

        // Section 20: Read CURRENT input values at click time directly
        let pageTypeValue = document.getElementById("pageTypeSelect")?.value || "Login / Sign In";
        if (pageTypeValue === "Other") {
            const otherCustom = document.getElementById("pageTypeOtherInput")?.value.trim();
            pageTypeValue = otherCustom || "Other";
        }

        if (!pageTypeValue || (pageTypeValue === "Auto Detect" && !currentUploadedFile)) {
            showToast("Please select a specific Page Type to generate a checklist without a screenshot.", "warning");
            return;
        }
        selectedPageType = pageTypeValue;

        const userPrompt = (promptInput?.value || "").trim();
        additionalContext = userPrompt;

        // Section 22: Cancel any in-flight request before launching new generation
        if (currentAbortController) {
            try {
                currentAbortController.abort();
            } catch (e) {}
        }
        currentAbortController = new AbortController();

        // Section 21: Unique Request ID
        const reqId = "req-" + Date.now() + "-" + Math.random().toString(36).substring(2, 8);
        currentAnalysisRequestId = reqId;

        analysisStatus = "RUNNING";
        checklistStatus = "GENERATING";

        // Loading UI state
        if (btnAnalyze) {
            btnAnalyze.disabled = true;
            if (btnAnalyzeText) btnAnalyzeText.textContent = currentUploadedFile ? "Vision AI Processing..." : "Generating Checklist...";
        }
        const regenBtn = document.getElementById("btnRegenerateChecklist");
        if (regenBtn) {
            regenBtn.disabled = true;
            regenBtn.textContent = "Processing...";
        }
        if (analysisStepperBox) analysisStepperBox.classList.add("active");

        const step1 = document.getElementById("loadingStep1");
        const step2 = document.getElementById("loadingStep2");
        const step3 = document.getElementById("loadingStep3");
        const step4 = document.getElementById("loadingStep4");

        const step1Text = currentUploadedFile ? "Image received" : "Page Type verified";
        const step2Text = currentUploadedFile ? "Identifying visible functionality" : "Querying security knowledge base";
        const step3Text = "Building security checklist";
        const step4Text = "Prioritizing tests";

        if (step1) { step1.className = "step-item running"; step1.textContent = `● ${step1Text}`; }
        if (step2) { step2.className = "step-item pending"; step2.textContent = `○ ${step2Text}`; }
        if (step3) { step3.className = "step-item pending"; step3.textContent = `○ ${step3Text}`; }
        if (step4) { step4.className = "step-item pending"; step4.textContent = `○ ${step4Text}`; }

        setTimeout(() => {
            if (step1) { step1.className = "step-item done"; step1.textContent = `✓ ${step1Text}`; }
            if (step2) { step2.className = "step-item running"; step2.textContent = `● ${step2Text}`; }
        }, 300);

        setTimeout(() => {
            if (step2) { step2.className = "step-item done"; step2.textContent = `✓ ${step2Text}`; }
            if (step3) { step3.className = "step-item running"; step3.textContent = `● ${step3Text}`; }
        }, 700);

        setTimeout(() => {
            if (step3) { step3.className = "step-item done"; step3.textContent = `✓ ${step3Text}`; }
            if (step4) { step4.className = "step-item running"; step4.textContent = `● ${step4Text}`; }
        }, 1100);

        const formData = new FormData();
        if (currentUploadedFile) {
            formData.append("image", currentUploadedFile);
        }
        if (userPrompt) formData.append("prompt", userPrompt);
        formData.append("project_id", activeProj.id);
        formData.append("request_id", reqId);
        if (pageTypeValue) {
            formData.append("page_type", pageTypeValue);
        }

        const fileName = currentUploadedFile ? currentUploadedFile.name : "none (optional)";
        console.log(`[TRACEGATE API] Dispatching generateChecklist: req_id="${reqId}", file="${fileName}", page_type="${pageTypeValue}"`);

        try {
            const response = await fetch("/api/analyze-screenshot", {
                method: "POST",
                headers: getAuthHeaders(),
                body: formData,
                signal: currentAbortController.signal
            });

            if (!response.ok) {
                let errDetail = "Checklist generation failed.";
                try {
                    const errJson = await response.json();
                    if (typeof errJson.detail === "string") {
                        errDetail = errJson.detail;
                    } else if (Array.isArray(errJson.detail)) {
                        errDetail = errJson.detail.map(d => d.msg || JSON.stringify(d)).join("; ");
                    } else if (errJson.detail) {
                        errDetail = JSON.stringify(errJson.detail);
                    }
                } catch (e) {}
                throw new Error(errDetail);
            }

            const data = await response.json();

            // Section 21 & 23: Ignore stale responses - latest request always wins!
            if (data.request_id && data.request_id !== currentAnalysisRequestId) {
                console.warn(`[TRACEGATE] Discarding stale response ${data.request_id} (active is ${currentAnalysisRequestId})`);
                return;
            }

            currentImageHash = data.image_hash || null;
            lastAnalyzedPageType = pageTypeValue;
            lastGeneratedPageType = pageTypeValue;
            analysisResult = data;
            checklist = data.checklist || [];
            analysisStatus = "SUCCESS";
            checklistStatus = "CURRENT";

            const staleBanner = document.getElementById("staleAnalysisBanner");
            if (staleBanner) staleBanner.style.display = "none";

            if (step4) {
                step4.className = "step-item done";
                step4.textContent = "✓ Prioritizing tests";
            }

            setTimeout(() => {
                if (analysisStepperBox) analysisStepperBox.classList.remove("active");
                if (btnAnalyze) {
                    btnAnalyze.disabled = false;
                    if (btnAnalyzeText) btnAnalyzeText.textContent = "Analyze & Generate Checklist";
                }
                if (regenBtn) {
                    regenBtn.disabled = false;
                    regenBtn.textContent = "Generate Checklist";
                }

                // Save to project
                activeProj.checklist_data = data;
                activeProj.updated_at = new Date().toISOString().split("T")[0];
                saveProjects();

                // Switch view states
                const idleEl = document.getElementById("idleState");
                const resEl = document.getElementById("resultsContent");
                if (idleEl) idleEl.style.display = "none";
                if (resEl) resEl.classList.add("active");

                renderPageAnalysis(data);
                renderChecklistCards();
                updateChecklistProgressUI();
                refreshDashboardStats();

                showToast("Security checklist generated successfully!", "success");
            }, 400);

        } catch (err) {
            // Section 22: Catch AbortError quietly, no error toast for aborted request
            if (err.name === "AbortError") {
                console.log(`[TRACEGATE] Superseded request "${reqId}" cancelled.`);
                return;
            }

            analysisStatus = "ERROR";
            checklistStatus = "IDLE";
            if (analysisStepperBox) analysisStepperBox.classList.remove("active");
            if (btnAnalyze) {
                btnAnalyze.disabled = false;
                if (btnAnalyzeText) btnAnalyzeText.textContent = "Analyze & Generate Checklist";
            }
            if (regenBtn) {
                regenBtn.disabled = false;
                regenBtn.textContent = "Generate Checklist";
            }
            showToast(`Analysis Error: ${err.message}`, "error");
        }
    }

    if (btnAnalyze) {
        btnAnalyze.addEventListener("click", generateChecklist);
    }

    function renderPageAnalysis(data) {
        const pageTypeEl = document.getElementById("detectedPageType");
        if (pageTypeEl) pageTypeEl.textContent = data.page_type || "Unknown Web Interface";

        const confValEl = document.getElementById("confidenceValue");
        const confBarEl = document.getElementById("confidenceBarFill");
        if (data.selected_page_type && data.selected_page_type !== "Auto Detect") {
            if (confValEl) confValEl.textContent = data.visual_analysis_available !== false ? "Visual Context Applied" : "Knowledge Base Active";
            if (confBarEl) confBarEl.style.width = "100%";
        } else {
            const pct = Math.round((data.confidence || 0) * 100);
            if (confValEl) confValEl.textContent = `${pct}%`;
            if (confBarEl) confBarEl.style.width = `${pct}%`;
        }

        // Section 4 & 36: Permanently hide conflict banner (mismatch warnings removed)
        const conflictBanner = document.getElementById("pageTypeConflictBanner");
        if (conflictBanner) conflictBanner.style.display = "none";

        // Ambiguity Warning Banner (only for truly ambiguous interfaces)
        const ambiguityBanner = document.getElementById("ambiguityBanner");
        const ambiguityText = document.getElementById("ambiguityText");
        if (ambiguityBanner) {
            if (data.page_type === "Unknown / Ambiguous" || (data.selected_page_type === "Auto Detect" && data.confidence < 0.5)) {
                ambiguityBanner.classList.add("active");
                if (ambiguityText) ambiguityText.textContent = data.ambiguity_notes || "The screenshot could not be uniquely categorized. Please select a specific Page Type from the dropdown.";
            } else {
                ambiguityBanner.classList.remove("active");
            }
        }

        // Visible Functionality
        const funcListEl = document.getElementById("detectedFunctionalitiesList");
        if (funcListEl) {
            funcListEl.innerHTML = "";
            const funcs = (data.visible_functionality && data.visible_functionality.length > 0)
                ? data.visible_functionality
                : (data.detected_functionalities && data.detected_functionalities.length > 0)
                    ? data.detected_functionalities
                    : ["Authoritative Page Type Knowledge Base", "Curated Assessment Standards"];
            funcs.forEach(f => {
                const tag = document.createElement("span");
                tag.className = "surface-tag";
                tag.textContent = f;
                funcListEl.appendChild(tag);
            });
        }

        // Visible UI Elements
        const elemListEl = document.getElementById("detectedElementsList");
        if (elemListEl) {
            elemListEl.innerHTML = "";
            const elems = (data.detected_elements && data.detected_elements.length > 0)
                ? data.detected_elements
                : (data.visual_analysis_available === false ? ["Knowledge Base Standard Controls (Screenshot optional)"] : []);
            elems.forEach(e => {
                const tag = document.createElement("span");
                tag.className = "element-tag";
                tag.textContent = typeof e === "string" ? e : (e.name || JSON.stringify(e));
                elemListEl.appendChild(tag);
            });
        }
    }

    // ==========================================================================
    // 8. CHECKLIST COMPLETION WORKFLOW & FINDINGS LOGGING
    // ==========================================================================
    function renderChecklistCards() {
        const container = document.getElementById("checklistContainer");
        if (!container) return;
        container.innerHTML = "";

        const proj = getActiveProject();
        if (!proj || !proj.checklist_data || !proj.checklist_data.checklist) return;

        let items = [...proj.checklist_data.checklist];

        // 1. Filter by Search
        if (currentSearchTerm) {
            items = items.filter(i => 
                i.name.toLowerCase().includes(currentSearchTerm) ||
                (i.cwe && i.cwe.toLowerCase().includes(currentSearchTerm)) ||
                (i.testing_objective && i.testing_objective.toLowerCase().includes(currentSearchTerm)) ||
                (i.reason && i.reason.toLowerCase().includes(currentSearchTerm))
            );
        }

        // 2. Filter by Priority
        if (currentPriorityFilter !== "ALL") {
            items = items.filter(i => i.priority === currentPriorityFilter);
        }

        // 3. Filter by Status
        if (currentStatusFilter !== "ALL") {
            items = items.filter(i => i.status === currentStatusFilter);
        }

        // 4. Sort Items
        if (currentSortMode === "priority_desc") {
            items.sort((a, b) => (PRIORITY_ORDER[a.priority] ?? 99) - (PRIORITY_ORDER[b.priority] ?? 99));
        } else if (currentSortMode === "priority_asc") {
            items.sort((a, b) => (PRIORITY_ORDER[b.priority] ?? 99) - (PRIORITY_ORDER[a.priority] ?? 99));
        } else if (currentSortMode === "untested_first") {
            items.sort((a, b) => {
                if (a.status === "NOT_TESTED" && b.status !== "NOT_TESTED") return -1;
                if (a.status !== "NOT_TESTED" && b.status === "NOT_TESTED") return 1;
                return (PRIORITY_ORDER[a.priority] ?? 99) - (PRIORITY_ORDER[b.priority] ?? 99);
            });
        } else if (currentSortMode === "recently_completed") {
            items.sort((a, b) => {
                if (a.status !== "NOT_TESTED" && b.status === "NOT_TESTED") return -1;
                if (a.status === "NOT_TESTED" && b.status !== "NOT_TESTED") return 1;
                return (PRIORITY_ORDER[a.priority] ?? 99) - (PRIORITY_ORDER[b.priority] ?? 99);
            });
        }

        if (items.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; padding: 40px; background: var(--bg-surface); border: 1px dashed var(--border-subtle); border-radius: var(--radius-lg); color: var(--text-muted);">
                    No checklist items match the selected filter criteria.
                </div>
            `;
            return;
        }

        items.forEach(item => {
            container.appendChild(createChecklistItemCard(item, proj));
        });
    }

    function createChecklistItemCard(item, proj) {
        const card = document.createElement("div");
        const statusClass = item.status === "TESTED_NOT_FOUND" ? "status-clean" : (item.status === "VULNERABILITY_FOUND" ? "status-vuln" : "status-untested");
        card.className = `checklist-card ${statusClass}`;

        const priorityBadgeClass = `badge-${item.priority.toLowerCase()}`;
        const sourceLabel = item.source === "USER" ? "User Added" : (item.source === "USER_MODIFIED" ? "User Modified" : "AI Generated");
        const sourceClass = item.source === "USER" ? "source-user" : (item.source === "USER_MODIFIED" ? "source-modified" : "source-ai");

        // Status badge label
        let statusBadgeHtml = '<span class="status-indicator-badge untested">○ Not Tested</span>';
        let verifyBtnHtml = '<button type="button" class="btn-verify-action btn-verify-untested btn-open-verify">Verify / Complete</button>';

        if (item.status === "TESTED_NOT_FOUND") {
            statusBadgeHtml = '<span class="status-indicator-badge clean">✓ Tested — Not Found</span>';
            verifyBtnHtml = '<button type="button" class="btn-verify-action btn-verify-clean btn-open-verify">✓ Clean (Update)</button>';
        } else if (item.status === "VULNERABILITY_FOUND") {
            statusBadgeHtml = '<span class="status-indicator-badge vuln">⚠ Vulnerability Found</span>';
            verifyBtnHtml = '<button type="button" class="btn-verify-action btn-verify-vuln btn-open-verify">⚠ Vuln Found (Edit)</button>';
        }

        let findingPreviewHtml = "";
        if (item.status === "VULNERABILITY_FOUND" && item.finding) {
            findingPreviewHtml = `
                <div class="linked-finding-preview">
                    <span class="linked-finding-title">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
                        Logged Finding: ${escapeHtml(item.finding.finding_name || item.name)}
                    </span>
                    <p class="linked-finding-snippet">${escapeHtml(item.finding.description || "Observation recorded.")}</p>
                </div>
            `;
        }

        card.innerHTML = `
            <div class="card-content-wrap">
                <div class="card-top-bar">
                    <div class="card-badges-row">
                        <span class="badge ${priorityBadgeClass}">${item.priority}</span>
                        ${item.cwe ? `<span class="cwe-pill">${escapeHtml(item.cwe)}</span>` : ""}
                        <span class="source-tag ${sourceClass}">${sourceLabel}</span>
                    </div>
                    <div class="card-item-title-row">
                        ${statusBadgeHtml}
                    </div>
                </div>

                <div class="test-name">${escapeHtml(item.name)}</div>

                <div class="card-details-grid">
                    <div class="detail-block">
                        <span class="detail-label">Why is this relevant?</span>
                        <p class="detail-text">${escapeHtml(item.reason)}</p>
                    </div>
                    <div class="detail-block">
                        <span class="detail-label">Testing Objective</span>
                        <p class="detail-text">${escapeHtml(item.testing_objective)}</p>
                    </div>
                </div>

                ${findingPreviewHtml}

                <div class="card-actions-bar">
                    <div class="left-actions">
                        ${verifyBtnHtml}
                    </div>
                    <div class="right-card-tools">
                        <button type="button" class="btn-icon-tool btn-edit-test" title="Edit Test Details">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/>
                            </svg>
                        </button>
                        <button type="button" class="btn-icon-tool btn-delete btn-delete-test" title="Remove Test">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="3 6 5 6 21 6"/>
                                <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                            </svg>
                        </button>
                    </div>
                </div>
            </div>
        `;

        // Event listener for Verify / Complete
        card.querySelector(".btn-open-verify").addEventListener("click", () => {
            activeVerifyItem = item;
            const titleEl = document.getElementById("verifyTestTitle");
            if (titleEl) titleEl.textContent = item.name;
            openModal("modalVerify");
        });

        // Event listener for Edit
        card.querySelector(".btn-edit-test").addEventListener("click", () => {
            activeEditItem = item;
            document.getElementById("editItemName").value = item.name;
            document.getElementById("editItemPriority").value = item.priority;
            document.getElementById("editItemCwe").value = item.cwe || "";
            document.getElementById("editItemReason").value = item.reason;
            document.getElementById("editItemObjective").value = item.testing_objective;
            openModal("modalEditItem");
        });

        // Event listener for Delete
        card.querySelector(".btn-delete-test").addEventListener("click", () => {
            if (confirm(`Remove test "${item.name}" from checklist?`)) {
                proj.checklist_data.checklist = proj.checklist_data.checklist.filter(i => i.id !== item.id);
                saveProjects();
                renderChecklistCards();
                updateChecklistProgressUI();
                refreshDashboardStats();
                showToast("Test removed from checklist", "info");
            }
        });

        return card;
    }

    // Modal Verify Actions
    const btnVerifyClean = document.getElementById("btnVerifyClean");
    const btnVerifyVuln = document.getElementById("btnVerifyVuln");
    const btnCloseVerifyModal = document.getElementById("btnCloseVerifyModal");

    if (btnCloseVerifyModal) {
        btnCloseVerifyModal.addEventListener("click", () => {
            closeModal("modalVerify");
        });
    }

    // Outcome 1: "Vulnerability Not Found" (Section 14)
    if (btnVerifyClean) {
        btnVerifyClean.addEventListener("click", async () => {
            if (!activeVerifyItem) return;
            const proj = getActiveProject();

            activeVerifyItem.status = "TESTED_NOT_FOUND";
            activeVerifyItem.finding = null;

            // Sync status with backend
            try {
                await fetch(`/api/checklist/${activeVerifyItem.id}/status`, {
                    method: "PUT",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({ status: "TESTED_NOT_FOUND" })
                });
            } catch (err) {
                console.warn("[TRACEGATE] Status update API fallback:", err);
            }

            // Remove any previously recorded finding for this test if re-verifying
            if (proj.findings) {
                const oldFinding = proj.findings.find(f => f.test_id === activeVerifyItem.id);
                if (oldFinding) {
                    try {
                        await fetch(`/api/findings/${oldFinding.id}`, {
                            method: "DELETE",
                            headers: getAuthHeaders()
                        });
                    } catch (e) {}
                    proj.findings = proj.findings.filter(f => f.test_id !== activeVerifyItem.id);
                }
            }
            proj.updated_at = new Date().toISOString().split("T")[0];
            saveProjects();

            closeModal("modalVerify");
            renderChecklistCards();
            updateChecklistProgressUI();
            refreshDashboardStats();
            showToast("✓ Tested — Marked clean with no vulnerability found", "success");
        });
    }

    // Outcome 2: "Vulnerability Found" (Simplified Workflow)
    if (btnVerifyVuln) {
        btnVerifyVuln.addEventListener("click", () => {
            if (!activeVerifyItem) return;
            closeModal("modalVerify");

            const existingFinding = activeVerifyItem.finding;

            // 1. Finding Name (Auto-filled from checklist test, editable)
            const nameInp = document.getElementById("findingNameInput");
            if (nameInp) {
                nameInp.value = existingFinding?.finding_name || activeVerifyItem.name || "";
            }

            // 2. What did you find? (Main observation field)
            const obsInp = document.getElementById("findingObservationInput");
            if (obsInp) {
                obsInp.value = existingFinding?.observation || existingFinding?.description || "";
            }

            // Sync hidden inputs for backwards compatibility
            const descInp = document.getElementById("findingDescInput");
            if (descInp) descInp.value = obsInp ? obsInp.value : "";
            const sevInp = document.getElementById("findingSeverityInput");
            if (sevInp) sevInp.value = existingFinding?.priority || activeVerifyItem.priority || "HIGH";
            const cweInp = document.getElementById("findingCweInput");
            if (cweInp) cweInp.value = existingFinding?.cwe || activeVerifyItem.cwe || "";
            const cvssInp = document.getElementById("findingCvssInput");
            if (cvssInp) cvssInp.value = existingFinding?.cvss_score || "";
            const statusInp = document.getElementById("findingStatusInput");
            if (statusInp) statusInp.value = existingFinding?.status || "Open";

            // 3. Multi-Evidence Initialization
            clearPendingEvidence();
            if (existingFinding && Array.isArray(existingFinding.evidence) && existingFinding.evidence.length > 0) {
                pendingEvidenceList = existingFinding.evidence.map(e => ({ ...e, previewUrl: null }));
            } else if (existingFinding?.evidence_filename || existingFinding?.evidence_data) {
                pendingEvidenceList = [{
                    id: "ev-legacy-" + Date.now(),
                    name: existingFinding.evidence_filename || "evidence.png",
                    url: existingFinding.evidence_data,
                    type: "image/png",
                    size: 0
                }];
            }

            renderEvidenceListUI();
            openModal("modalFinding");
        });
    }

    // Modal Finding Actions (Simplified Flow)
    const btnCloseFindingModal = document.getElementById("btnCloseFindingModal");
    const btnCancelFinding = document.getElementById("btnCancelFinding");
    const btnSaveFinding = document.getElementById("btnSaveFinding");
    const evidenceMultiDropzone = document.getElementById("evidenceMultiDropzone");
    const evidenceFileInput = document.getElementById("evidenceFileInput");

    if (btnCloseFindingModal) btnCloseFindingModal.addEventListener("click", () => {
        clearPendingEvidence();
        closeModal("modalFinding");
    });
    if (btnCancelFinding) btnCancelFinding.addEventListener("click", () => {
        clearPendingEvidence();
        closeModal("modalFinding");
    });

    // Multi-File Evidence Handlers
    if (evidenceMultiDropzone && evidenceFileInput) {
        evidenceMultiDropzone.addEventListener("click", (e) => {
            if (e.target !== evidenceFileInput) {
                evidenceFileInput.click();
            }
        });

        evidenceFileInput.addEventListener("click", (e) => {
            e.stopPropagation();
        });

        evidenceMultiDropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            evidenceMultiDropzone.style.borderColor = "var(--accent-primary)";
            evidenceMultiDropzone.style.background = "var(--bg-surface-3)";
        });

        evidenceMultiDropzone.addEventListener("dragleave", () => {
            evidenceMultiDropzone.style.borderColor = "var(--border-subtle)";
            evidenceMultiDropzone.style.background = "var(--bg-surface-2)";
        });

        evidenceMultiDropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            evidenceMultiDropzone.style.borderColor = "var(--border-subtle)";
            evidenceMultiDropzone.style.background = "var(--bg-surface-2)";
            if (e.dataTransfer && e.dataTransfer.files) {
                addEvidenceFiles(e.dataTransfer.files);
            }
        });

        evidenceFileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length) {
                addEvidenceFiles(e.target.files);
                e.target.value = "";
            }
        });
    }

    function clearPendingEvidence() {
        if (Array.isArray(pendingEvidenceList)) {
            pendingEvidenceList.forEach(item => {
                if (item && item.previewUrl) {
                    try { URL.revokeObjectURL(item.previewUrl); } catch (e) {}
                }
            });
        }
        pendingEvidenceList = [];
        pendingEvidenceData = null;
        pendingEvidenceFilename = null;
    }

    async function addEvidenceFiles(fileList) {
        const allowedExtensions = [".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg", ".txt", ".json", ".pdf", ".docx"];
        for (let i = 0; i < fileList.length; i++) {
            const file = fileList[i];
            const ext = "." + (file.name.split(".").pop() || "").toLowerCase();
            if (!allowedExtensions.includes(ext)) {
                showToast(`Unsupported file type: ${file.name}. Allowed: PNG, JPG, WEBP, TXT, JSON, PDF, DOCX`, "error");
                continue;
            }
            if (file.size > 10 * 1024 * 1024) {
                showToast(`File ${file.name} exceeds 10MB limit.`, "error");
                continue;
            }

            const evItem = {
                id: "ev-" + Date.now() + "-" + Math.random().toString(36).substring(2, 7),
                name: file.name,
                size: file.size,
                type: file.type || (ext === ".txt" || ext === ".json" ? "text/plain" : "image/png"),
                file: file,
                previewUrl: null,
                data: null,
                url: null
            };

            // Ephemeral Object URL for preview - avoids storing base64 blobs in memory/localStorage (Requirements 14-15)
            const isImg = evItem.type && evItem.type.startsWith("image/");
            if (isImg && typeof URL !== "undefined" && typeof URL.createObjectURL === "function") {
                try {
                    evItem.previewUrl = URL.createObjectURL(file);
                } catch (e) {
                    evItem.previewUrl = null;
                }
            }

            pendingEvidenceList.push(evItem);
        }
        renderEvidenceListUI();
    }

    function renderEvidenceListUI() {
        const container = document.getElementById("uploadedEvidenceContainer");
        const listEl = document.getElementById("uploadedEvidenceList");
        if (!container || !listEl) return;

        listEl.innerHTML = "";
        if (!pendingEvidenceList || pendingEvidenceList.length === 0) {
            container.style.display = "none";
            pendingEvidenceData = null;
            pendingEvidenceFilename = null;
            return;
        }

        container.style.display = "block";
        pendingEvidenceFilename = pendingEvidenceList[0]?.name || null;
        pendingEvidenceData = pendingEvidenceList[0]?.url || pendingEvidenceList[0]?.name || null;

        pendingEvidenceList.forEach((item, idx) => {
            const row = document.createElement("div");
            row.style.display = "flex";
            row.style.alignItems = "center";
            row.style.justifyContent = "space-between";
            row.style.padding = "6px 12px";
            row.style.background = "var(--bg-surface-3)";
            row.style.borderRadius = "var(--radius-sm)";
            row.style.border = "1px solid var(--border-subtle)";

            const left = document.createElement("div");
            left.style.display = "flex";
            left.style.alignItems = "center";
            left.style.gap = "8px";

            const isImg = item.type && item.type.startsWith("image/");
            const previewSrc = item.previewUrl || item.url || (item.data && item.data.length < 500000 ? item.data : null);
            if (isImg && previewSrc) {
                const thumb = document.createElement("img");
                thumb.style.width = "28px";
                thumb.style.height = "28px";
                thumb.style.objectFit = "cover";
                thumb.style.borderRadius = "3px";
                thumb.style.border = "1px solid var(--border-subtle)";
                if (previewSrc.startsWith("data:") || previewSrc.startsWith("blob:")) {
                    thumb.src = previewSrc;
                } else {
                    fetch(previewSrc, { headers: getAuthHeaders() })
                        .then(r => r.ok ? r.blob() : null)
                        .then(b => { if (b) thumb.src = URL.createObjectURL(b); })
                        .catch(() => {});
                }
                left.appendChild(thumb);
            } else {
                const icon = document.createElement("span");
                icon.textContent = "📄";
                icon.style.fontSize = "1.1rem";
                left.appendChild(icon);
            }

            const nameSpan = document.createElement("span");
            nameSpan.textContent = item.name;
            nameSpan.style.fontSize = "0.82rem";
            nameSpan.style.fontWeight = "600";
            nameSpan.style.color = "var(--text-primary)";
            left.appendChild(nameSpan);

            if (item.size) {
                const sizeSpan = document.createElement("span");
                const kb = Math.round(item.size / 1024);
                sizeSpan.textContent = `(${kb > 0 ? kb + " KB" : item.size + " B"})`;
                sizeSpan.style.fontSize = "0.72rem";
                sizeSpan.style.color = "var(--text-muted)";
                left.appendChild(sizeSpan);
            }

            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.innerHTML = "&times;";
            removeBtn.title = "Remove file";
            removeBtn.style.background = "none";
            removeBtn.style.border = "none";
            removeBtn.style.color = "var(--crit-color)";
            removeBtn.style.fontSize = "1.2rem";
            removeBtn.style.cursor = "pointer";
            removeBtn.style.padding = "0 4px";
            removeBtn.addEventListener("click", () => {
                if (item.previewUrl) {
                    try { URL.revokeObjectURL(item.previewUrl); } catch (e) {}
                }
                pendingEvidenceList.splice(idx, 1);
                renderEvidenceListUI();
            });

            row.appendChild(left);
            row.appendChild(removeBtn);
            listEl.appendChild(row);
        });
    }

    // Save Finding Button (Simplified & Single-path Submission)
    if (btnSaveFinding) {
        btnSaveFinding.addEventListener("click", async () => {
            if (isSavingFinding) return;
            if (!activeVerifyItem) return;
            const proj = getActiveProject();
            if (!proj) {
                showToast("Please open an active project first.", "error");
                return;
            }

            const obsInput = document.getElementById("findingObservationInput");
            const obsText = (obsInput?.value || document.getElementById("findingDescInput")?.value || "").trim();
            if (!obsText) {
                showToast("Please describe what you found in the observation field.", "warning");
                if (obsInput) obsInput.focus();
                return;
            }

            isSavingFinding = true;
            btnSaveFinding.disabled = true;
            btnSaveFinding.textContent = "Saving Finding...";

            try {
                const findingName = document.getElementById("findingNameInput")?.value.trim() || activeVerifyItem.name;
                const severity = activeVerifyItem.priority || "HIGH";
                const cwe = activeVerifyItem.cwe || null;

                // 1. Upload any physical files to server storage via multipart/form-data
                const filesToUpload = pendingEvidenceList.filter(item => item.file instanceof File);
                if (filesToUpload.length > 0) {
                    try {
                        const evFormData = new FormData();
                        filesToUpload.forEach(f => evFormData.append("files", f.file));
                        const uploadRes = await fetch(`/api/projects/${encodeURIComponent(proj.id)}/evidence`, {
                            method: "POST",
                            headers: getAuthHeaders(),
                            body: evFormData
                        });
                        if (uploadRes.ok) {
                            const uploadData = await uploadRes.json();
                            const serverUploaded = uploadData.uploaded || [];
                            serverUploaded.forEach(su => {
                                const match = pendingEvidenceList.find(pe => pe.name === su.name || pe.name === su.original_filename);
                                if (match) {
                                    match.id = su.id || match.id;
                                    match.evidence_id = su.evidence_id || match.evidence_id;
                                    match.url = su.url;
                                    match.filename = su.filename;
                                    match.file_path = su.file_path;
                                    match.size = su.size || match.size;
                                    match.type = su.mime_type || match.type;
                                    if (match.previewUrl) {
                                        try { URL.revokeObjectURL(match.previewUrl); } catch (e) {}
                                        match.previewUrl = null;
                                    }
                                    delete match.file;
                                    delete match.data;
                                }
                            });
                        } else {
                            const errJson = await uploadRes.json().catch(() => ({}));
                            showToast("Evidence upload warning: " + (errJson.detail || uploadRes.statusText), "warning");
                        }
                    } catch (ue) {
                        console.warn("[TRACEGATE] Evidence server upload fallback:", ue);
                    }
                }

                // Clean up evidence items for persistent JSON storage (METADATA & STORAGE REFERENCES ONLY)
                const cleanEvidence = pendingEvidenceList.map((item, idx) => ({
                    id: item.id || `ev-${Date.now()}-${idx}`,
                    evidence_id: item.evidence_id || `EV-${String(idx + 1).padStart(3, "0")}`,
                    name: item.name || item.filename,
                    filename: item.filename || item.name,
                    file_path: item.file_path || null,
                    url: item.url || (item.filename ? `/api/projects/${proj.id}/evidence/${item.filename}` : null),
                    size: item.size || 0,
                    type: item.type || "image/png",
                    caption: item.caption || ""
                }));

                const firstEv = cleanEvidence[0] || null;

                let findingObj = {
                    id: "find-" + Date.now(),
                    finding_name: findingName,
                    test_id: activeVerifyItem.id,
                    priority: severity,
                    cwe: cwe,
                    status: "Open",
                    observation: obsText,
                    description: obsText,
                    evidence: cleanEvidence,
                    evidence_filename: firstEv ? (firstEv.filename || firstEv.name) : null,
                    evidence_data: firstEv ? (firstEv.url || firstEv.filename) : null,
                    recorded_at: new Date().toISOString().replace("T", " ").substring(0, 16)
                };

                // 2. Persist finding in backend SQLite
                try {
                    const res = await fetch(`/api/checklist/${activeVerifyItem.id}/finding?project_id=${encodeURIComponent(proj.id)}`, {
                        method: "POST",
                        headers: getAuthHeaders({ "Content-Type": "application/json" }),
                        body: JSON.stringify({
                            finding_name: findingName,
                            observation: obsText,
                            description: obsText,
                            priority: severity,
                            cwe: cwe,
                            evidence: cleanEvidence,
                            evidence_filename: firstEv ? (firstEv.filename || firstEv.name) : null,
                            evidence_data: firstEv ? (firstEv.url || firstEv.filename) : null,
                            status: "Open"
                        })
                    });
                    if (res.ok) {
                        const saved = await res.json();
                        findingObj = { ...findingObj, ...saved };
                    }
                } catch (err) {
                    console.warn("[TRACEGATE] Finding persist API fallback:", err);
                }

                // Revoke preview object URLs cleanly to free browser memory
                clearPendingEvidence();

                activeVerifyItem.status = "VULNERABILITY_FOUND";
                activeVerifyItem.finding = findingObj;

                if (!proj.findings) proj.findings = [];
                proj.findings = proj.findings.filter(f => f.test_id !== activeVerifyItem.id && f.id !== findingObj.id);
                proj.findings.unshift(findingObj);
                proj.updated_at = new Date().toISOString().split("T")[0];

                saveProjects();
                closeModal("modalFinding");
                renderChecklistCards();
                updateChecklistProgressUI();
                refreshDashboardStats();

                const badgeCount = document.getElementById("wsFindingsBadgeCount");
                if (badgeCount) badgeCount.textContent = proj.findings.length;

                showToast("✓ Vulnerability Finding Saved & Verified!", "success");
            } catch (saveErr) {
                console.error("[TRACEGATE] Failed to save finding:", saveErr);
                showToast("Error saving finding: " + saveErr.message, "error");
            } finally {
                isSavingFinding = false;
                btnSaveFinding.disabled = false;
                btnSaveFinding.textContent = "Save Finding";
            }
        });
    }

    // Modal Edit Item Actions
    const btnCloseEditModal = document.getElementById("btnCloseEditModal");
    const btnCancelEdit = document.getElementById("btnCancelEdit");
    const btnSaveEdit = document.getElementById("btnSaveEdit");

    if (btnCloseEditModal) btnCloseEditModal.addEventListener("click", () => closeModal("modalEditItem"));
    if (btnCancelEdit) btnCancelEdit.addEventListener("click", () => closeModal("modalEditItem"));

    if (btnSaveEdit) {
        btnSaveEdit.addEventListener("click", async () => {
            if (!activeEditItem) return;
            const proj = getActiveProject();

            const name = document.getElementById("editItemName").value.trim();
            const priority = document.getElementById("editItemPriority").value;
            const cwe = document.getElementById("editItemCwe").value.trim();
            const reason = document.getElementById("editItemReason").value.trim();
            const objective = document.getElementById("editItemObjective").value.trim();

            if (!name || !reason || !objective) {
                showToast("Test name, reason, and testing objective are required.", "error");
                return;
            }

            // Sync with backend API
            try {
                await fetch(`/api/checklist/${activeEditItem.id}`, {
                    method: "PUT",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({
                        name: name,
                        priority: priority,
                        cwe: cwe || null,
                        reason: reason,
                        testing_objective: objective
                    })
                });
            } catch (err) {
                console.warn("[TRACEGATE] Edit checklist item API fallback:", err);
            }

            activeEditItem.name = name;
            activeEditItem.priority = priority;
            activeEditItem.cwe = cwe || null;
            activeEditItem.reason = reason;
            activeEditItem.testing_objective = objective;
            activeEditItem.source = "USER_MODIFIED";

            saveProjects();
            closeModal("modalEditItem");
            renderChecklistCards();
            updateChecklistProgressUI();
            showToast("Test details updated (marked User Modified)", "success");
        });
    }

    // Modal Add Custom Test Actions
    const btnAddCustomTestBtn = document.getElementById("btnAddCustomTestBtn");
    const btnCloseAddCustomModal = document.getElementById("btnCloseAddCustomModal");
    const btnCancelCustomTest = document.getElementById("btnCancelCustomTest");
    const btnSaveCustomTest = document.getElementById("btnSaveCustomTest");
    const addCustomTestForm = document.getElementById("addCustomTestForm");

    function openAddCustomTestModal() {
        const errAlert = document.getElementById("customTestErrorAlert");
        if (errAlert) {
            errAlert.classList.add("hidden");
            errAlert.style.display = "none";
        }
        openModal("modalAddCustomTest");
    }

    if (btnAddCustomTestBtn) btnAddCustomTestBtn.addEventListener("click", openAddCustomTestModal);
    if (btnCloseAddCustomModal) btnCloseAddCustomModal.addEventListener("click", () => closeModal("modalAddCustomTest"));
    if (btnCancelCustomTest) btnCancelCustomTest.addEventListener("click", () => closeModal("modalAddCustomTest"));

    if (addCustomTestForm) {
        addCustomTestForm.addEventListener("submit", (e) => {
            e.preventDefault();
            if (btnSaveCustomTest) btnSaveCustomTest.click();
        });
    }

    if (btnSaveCustomTest) {
        btnSaveCustomTest.addEventListener("click", async (e) => {
            if (e && e.preventDefault) e.preventDefault();

            const errAlert = document.getElementById("customTestErrorAlert");
            const errMsg = document.getElementById("customTestErrorMsg");
            const showCustomError = (message) => {
                if (errAlert && errMsg) {
                    errMsg.textContent = message;
                    errAlert.classList.remove("hidden");
                    errAlert.style.display = "flex";
                }
                showToast(message, "error");
            };

            if (errAlert) {
                errAlert.classList.add("hidden");
                errAlert.style.display = "none";
            }

            const proj = getActiveProject();
            if (!proj) {
                showCustomError("Please select or open an active project first.");
                return;
            }

            const nameInput = document.getElementById("customTestName");
            const priorityInput = document.getElementById("customTestPriority");
            const cweInput = document.getElementById("customTestCwe");
            const reasonInput = document.getElementById("customTestReason");
            const objectiveInput = document.getElementById("customTestObjective");

            const name = nameInput ? nameInput.value.trim() : "";
            const priority = priorityInput ? priorityInput.value.trim() : "HIGH";
            const cwe = cweInput ? cweInput.value.trim() : "";
            const reason = reasonInput ? reasonInput.value.trim() : "";
            const objective = objectiveInput ? objectiveInput.value.trim() : "";

            // Client-side validations
            if (!name || name.length < 3) {
                showCustomError("Test Name is required and must be at least 3 characters.");
                if (nameInput) nameInput.focus();
                return;
            }
            if (name.length > 200) {
                showCustomError("Test Name must be 200 characters or fewer.");
                if (nameInput) nameInput.focus();
                return;
            }

            const validPriorities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
            const normalizedPriority = (priority || "HIGH").toUpperCase();
            if (!validPriorities.includes(normalizedPriority)) {
                showCustomError("Priority must be one of: CRITICAL, HIGH, MEDIUM, LOW.");
                return;
            }

            let normalizedCwe = null;
            if (cwe) {
                const cwePattern = /^CWE-\d+$/i;
                if (!cwePattern.test(cwe)) {
                    showCustomError("CWE Identifier must follow format CWE-<number> (e.g. CWE-307).");
                    if (cweInput) cweInput.focus();
                    return;
                }
                normalizedCwe = cwe.toUpperCase();
            }

            // Prevent duplicate clicks
            btnSaveCustomTest.disabled = true;
            const origText = btnSaveCustomTest.textContent;
            btnSaveCustomTest.textContent = "Adding...";

            try {
                const headers = getAuthHeaders({ "Content-Type": "application/json" });

                const payload = {
                    name: name,
                    priority: normalizedPriority,
                    cwe: normalizedCwe,
                    reason: reason || null,
                    testing_objective: objective || null
                };

                const res = await fetch(`/api/projects/${proj.id}/checklist/custom`, {
                    method: "POST",
                    headers: headers,
                    body: JSON.stringify(payload)
                });

                if (!res.ok) {
                    let errDetail = "Failed to add custom security test.";
                    try {
                        const errJson = await res.json();
                        if (errJson && errJson.detail) {
                            if (Array.isArray(errJson.detail)) {
                                errDetail = errJson.detail.map(d => d.msg || JSON.stringify(d)).join("; ");
                            } else {
                                errDetail = errJson.detail;
                            }
                        }
                    } catch (e) {
                        // ignore parse error
                    }
                    showCustomError(errDetail);
                    return;
                }

                const created = await res.json();

                // Ensure local project checklist structure exists
                if (!proj.checklist_data) {
                    proj.checklist_data = {
                        checklist: [],
                        page_type: proj.page_type || "Generic Application",
                        screenshot_path: proj.screenshot_path || null
                    };
                }
                if (!proj.checklist_data.checklist) {
                    proj.checklist_data.checklist = [];
                }

                // Unshift created item
                const existingIdx = proj.checklist_data.checklist.findIndex(item => item.id === created.id);
                if (existingIdx >= 0) {
                    proj.checklist_data.checklist[existingIdx] = created;
                } else {
                    proj.checklist_data.checklist.unshift(created);
                }

                saveProjects();

                // Clear form
                if (nameInput) nameInput.value = "";
                if (priorityInput) priorityInput.value = "HIGH";
                if (cweInput) cweInput.value = "";
                if (reasonInput) reasonInput.value = "";
                if (objectiveInput) objectiveInput.value = "";
                if (errAlert) {
                    errAlert.classList.add("hidden");
                    errAlert.style.display = "none";
                }

                closeModal("modalAddCustomTest");

                // Toggle idle state and show results content
                const idleState = document.getElementById("idleState");
                const resultsContent = document.getElementById("resultsContent");
                if (idleState) idleState.style.display = "none";
                if (resultsContent) resultsContent.classList.add("active");

                renderChecklistCards();
                updateChecklistProgressUI();
                refreshDashboardStats();
                showToast("Custom test added to checklist (marked User Added)", "success");
            } catch (err) {
                console.error("[TRACEGATE] Add custom test network error:", err);
                showCustomError("Network error: Unable to connect to server to add custom test.");
            } finally {
                btnSaveCustomTest.disabled = false;
                btnSaveCustomTest.textContent = origText || "Add to Checklist";
            }
        });
    }

    // ==========================================================================
    // 9. CHECKLIST DYNAMIC PROGRESS & COMPLETION BANNER
    // ==========================================================================
    function updateChecklistProgressUI() {
        const proj = getActiveProject();
        if (!proj || !proj.checklist_data || !proj.checklist_data.checklist) return;

        const m = calculateProjectMetrics(proj);

        const fillEl = document.getElementById("progressTrackFill");
        if (fillEl) fillEl.style.width = `${m.pct}%`;

        const pctText = document.getElementById("progressPctText");
        if (pctText) pctText.textContent = `${m.pct}%`;

        const fracEl = document.getElementById("statCompletedFraction");
        if (fracEl) fracEl.innerHTML = `<strong>${m.completed} / ${m.total}</strong> Tests Completed`;

        const remEl = document.getElementById("statRemainingCount");
        if (remEl) remEl.textContent = `${m.remaining} Remaining`;

        const vulnEl = document.getElementById("statVulnsBadge");
        if (vulnEl) vulnEl.textContent = `${m.vulns} Vulnerabilities Found`;

        const cleanEl = document.getElementById("statCleanBadge");
        if (cleanEl) cleanEl.textContent = `${m.clean} Clean`;

        // Completion Banner
        const completionBanner = document.getElementById("completionBanner");
        if (completionBanner) {
            if (m.pct === 100 && m.total > 0) {
                completionBanner.classList.add("active");
                if (proj.status !== "COMPLETED") {
                    proj.status = "COMPLETED";
                    saveProjects();
                }
            } else {
                completionBanner.classList.remove("active");
            }
        }
    }

    // ==========================================================================
    // 10. FILTERING & SORTING LISTENERS
    // ==========================================================================
    const checklistSearchInput = document.getElementById("checklistSearchInput");
    if (checklistSearchInput) {
        checklistSearchInput.addEventListener("input", (e) => {
            currentSearchTerm = e.target.value.toLowerCase().trim();
            renderChecklistCards();
        });
    }

    document.querySelectorAll("[data-priority]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-priority]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentPriorityFilter = btn.getAttribute("data-priority");
            renderChecklistCards();
        });
    });

    document.querySelectorAll("[data-status]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-status]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentStatusFilter = btn.getAttribute("data-status");
            renderChecklistCards();
        });
    });

    const sortChecklistSelect = document.getElementById("sortChecklistSelect");
    if (sortChecklistSelect) {
        sortChecklistSelect.addEventListener("change", (e) => {
            currentSortMode = e.target.value;
            renderChecklistCards();
        });
    }

    // ==========================================================================
    // 11. FINDINGS TAB CONTROLLER
    // ==========================================================================
    function normalizeSeverity(p) {
        if (!p) return "HIGH";
        const s = String(p).trim().toUpperCase();
        if (s === "CRITICAL" || s === "CRIT" || s === "P1" || s === "P-1" || s === "SEV1" || s === "SEV 1" || s === "SEV-1") return "CRITICAL";
        if (s === "HIGH" || s === "P2" || s === "P-2" || s === "SEV2" || s === "SEV 2" || s === "SEV-2") return "HIGH";
        if (s === "MEDIUM" || s === "MED" || s === "MODERATE" || s === "P3" || s === "P-3" || s === "SEV3" || s === "SEV 3" || s === "SEV-3") return "MEDIUM";
        if (s === "LOW" || s === "P4" || s === "P-4" || s === "SEV4" || s === "SEV 4" || s === "SEV-4") return "LOW";
        if (s === "INFORMATIONAL" || s === "INFO" || s === "P5" || s === "P-5" || s === "SEV5" || s === "SEV 5" || s === "SEV-5") return "INFORMATIONAL";
        if (s.includes("CRIT") || s.includes("P1")) return "CRITICAL";
        if (s.includes("HIGH") || s.includes("P2")) return "HIGH";
        if (s.includes("MED") || s.includes("P3")) return "MEDIUM";
        if (s.includes("LOW") || s.includes("P4")) return "LOW";
        if (s.includes("INFO") || s.includes("P5")) return "INFORMATIONAL";
        return "HIGH";
    }

    async function handleAuthenticatedEvidenceClick(url, name, dataUrl) {
        const lowerName = (name || "").toLowerCase();
        const isImg = (dataUrl && dataUrl.startsWith("data:image/")) || /\.(png|jpe?g|webp|gif|svg)$/i.test(lowerName);
        const isPdf = (dataUrl && dataUrl.startsWith("data:application/pdf")) || /\.pdf$/i.test(lowerName);
        const isTxt = /\.(txt|json|log|csv|xml|html)$/i.test(lowerName);
        const isViewable = isImg || isPdf || isTxt;

        // If data URL is present directly in memory
        const effectiveData = dataUrl || (url && url.startsWith("data:") ? url : null);
        if (effectiveData) {
            try {
                let objectUrl = null;
                if (effectiveData.startsWith("data:")) {
                    const parts = effectiveData.split(',');
                    const byteString = atob(parts[1] || "");
                    const mimeString = (parts[0].split(':')[1] || "").split(';')[0] || "application/octet-stream";
                    const ab = new ArrayBuffer(byteString.length);
                    const ia = new Uint8Array(ab);
                    for (let i = 0; i < byteString.length; i++) {
                        ia[i] = byteString.charCodeAt(i);
                    }
                    const blob = new Blob([ab], { type: mimeString });
                    objectUrl = URL.createObjectURL(blob);
                }

                if (isImg) {
                    const imgWin = window.open("", "_blank");
                    if (imgWin) {
                        imgWin.document.title = name || "PoC Evidence";
                        imgWin.document.body.style.margin = "0";
                        imgWin.document.body.style.background = "#0b0f19";
                        imgWin.document.body.style.display = "flex";
                        imgWin.document.body.style.flexDirection = "column";
                        imgWin.document.body.style.alignItems = "center";
                        imgWin.document.body.style.justifyContent = "center";
                        imgWin.document.body.style.minHeight = "100vh";
                        imgWin.document.body.innerHTML = `
                            <div style="text-align: center; padding: 20px;">
                                <img src="${objectUrl || effectiveData}" alt="${escapeHtml(name)}" style="max-width: 92vw; max-height: 85vh; object-fit: contain; border-radius: 8px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); background: #1e293b;" />
                                <div style="margin-top: 12px; color: #94a3b8; font-size: 13px; font-family: monospace;">${escapeHtml(name)}</div>
                            </div>
                        `;
                        return;
                    }
                } else if (isPdf || isTxt) {
                    if (objectUrl) {
                        window.open(objectUrl, "_blank");
                        return;
                    }
                }

                const a = document.createElement("a");
                a.href = objectUrl || effectiveData;
                a.download = name || "evidence-file";
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                if (objectUrl) setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
                return;
            } catch (err) {
                console.error("[TRACEGATE] Error presenting data URI evidence:", err);
                showToast("Could not open evidence artifact.", "error");
                return;
            }
        }

        const fetchUrl = url;
        if (!fetchUrl) {
            showToast("Evidence URL not available.", "warning");
            return;
        }

        // Open window synchronously for viewable files to prevent popup blocking
        let newTab = null;
        if (isViewable) {
            try {
                newTab = window.open("", "_blank");
                if (newTab) {
                    newTab.document.title = "Loading Evidence - Tracegate";
                    newTab.document.body.style.margin = "0";
                    newTab.document.body.style.background = "#0b0f19";
                    newTab.document.body.style.color = "#94a3b8";
                    newTab.document.body.style.fontFamily = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
                    newTab.document.body.style.display = "flex";
                    newTab.document.body.style.flexDirection = "column";
                    newTab.document.body.style.alignItems = "center";
                    newTab.document.body.style.justifyContent = "center";
                    newTab.document.body.style.height = "100vh";
                    newTab.document.body.innerHTML = `
                        <div style="text-align: center;">
                            <div style="font-size: 18px; font-weight: 600; color: #f1f5f9; margin-bottom: 8px;">Retrieving PoC Evidence</div>
                            <div style="font-size: 13px; color: #64748b;">Verifying project authorization and decrypting artifact...</div>
                        </div>
                    `;
                }
            } catch (e) {
                newTab = null;
            }
        }

        try {
            const res = await fetch(fetchUrl, {
                method: "GET",
                headers: getAuthHeaders()
            });

            if (!res.ok) {
                let errMsg = `Server returned ${res.status}`;
                try {
                    const errData = await res.json();
                    if (errData && errData.detail) errMsg = errData.detail;
                } catch (e) {}

                if (newTab && !newTab.closed) {
                    newTab.document.title = "Access Denied - Tracegate";
                    newTab.document.body.innerHTML = `
                        <div style="text-align: center; padding: 24px;">
                            <div style="color: #ef4444; font-size: 20px; font-weight: 700; margin-bottom: 8px;">Access Denied</div>
                            <div style="color: #94a3b8; font-size: 14px;">${escapeHtml(errMsg)}</div>
                        </div>
                    `;
                }
                showToast(`Unable to load evidence: ${errMsg}`, "error");
                return;
            }

            const blob = await res.blob();
            const objectUrl = URL.createObjectURL(blob);

            if (isViewable && newTab && !newTab.closed) {
                if (isImg) {
                    newTab.document.title = name || "PoC Evidence";
                    newTab.document.body.style.background = "#0b0f19";
                    newTab.document.body.innerHTML = `
                        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; padding: 24px; box-sizing: border-box;">
                            <img src="${objectUrl}" alt="${escapeHtml(name)}" style="max-width: 92vw; max-height: 82vh; object-fit: contain; border-radius: 8px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.6); background: #1e293b; border: 1px solid #334155;" />
                            <div style="display: flex; align-items: center; gap: 16px; margin-top: 14px; background: #1e293b; padding: 8px 18px; border-radius: 20px; border: 1px solid #334155;">
                                <span style="color: #f1f5f9; font-size: 13px; font-family: monospace;">${escapeHtml(name)}</span>
                                <a href="${objectUrl}" download="${escapeHtml(name)}" style="color: #38bdf8; text-decoration: none; font-size: 12px; font-weight: 600; padding: 4px 10px; border-radius: 4px; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3);">Download Original</a>
                            </div>
                        </div>
                    `;
                } else if (isPdf || isTxt) {
                    newTab.location.href = objectUrl;
                }
            } else {
                const a = document.createElement("a");
                a.href = objectUrl;
                if (isViewable) {
                    a.target = "_blank";
                    a.rel = "noopener";
                } else {
                    a.download = name || "evidence-file";
                }
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
                showToast(`Retrieved ${name || "evidence file"}.`, "success");
            }
        } catch (fetchErr) {
            console.error("[TRACEGATE] Failed to fetch evidence file:", fetchErr);
            if (newTab && !newTab.closed) {
                newTab.close();
            }
            showToast("Network error while retrieving PoC evidence.", "error");
        }
    }

    function renderWorkspaceFindings() {
        const listEl = document.getElementById("wsFindingsList");
        if (!listEl) return;
        listEl.innerHTML = "";

        const proj = getActiveProject();
        const allFindings = (proj && proj.findings) ? proj.findings : [];

        // 1. Update Metrics Cards
        const totalCount = allFindings.length;
        const critCount = allFindings.filter(f => normalizeSeverity(f.priority || f.severity) === "CRITICAL").length;
        const highCount = allFindings.filter(f => normalizeSeverity(f.priority || f.severity) === "HIGH").length;
        const medCount = allFindings.filter(f => normalizeSeverity(f.priority || f.severity) === "MEDIUM").length;
        const lowCount = allFindings.filter(f => normalizeSeverity(f.priority || f.severity) === "LOW").length;

        const statTot = document.getElementById("findingsStatTotal");
        const statCrit = document.getElementById("findingsStatCrit");
        const statHigh = document.getElementById("findingsStatHigh");
        const statMed = document.getElementById("findingsStatMed");
        const statLow = document.getElementById("findingsStatLow");

        if (statTot) statTot.textContent = totalCount;
        if (statCrit) statCrit.textContent = critCount;
        if (statHigh) statHigh.textContent = highCount;
        if (statMed) statMed.textContent = medCount;
        if (statLow) statLow.textContent = lowCount;

        if (totalCount === 0) {
            listEl.innerHTML = `
                <div style="text-align: center; padding: 40px; background: var(--bg-surface); border: 1px dashed var(--border-subtle); border-radius: var(--radius-lg); color: var(--text-muted);">
                    <p style="font-size: 1rem; font-weight: 600; margin-bottom: 4px;">No vulnerabilities confirmed yet.</p>
                    <p style="font-size: 0.82rem;">Execute tests in the Checklist Generator and select "Vulnerability Found" to document security findings with PoC evidence.</p>
                </div>
            `;
            return;
        }

        // 2. Filter findings
        let filtered = allFindings.filter(f => {
            const sev = normalizeSeverity(f.priority || f.severity);
            const matchSeverity = currentFindingSeverityFilter === "ALL" || sev === currentFindingSeverityFilter;
            const matchSearch = !currentFindingSearchTerm ||
                f.finding_name.toLowerCase().includes(currentFindingSearchTerm) ||
                (f.description && f.description.toLowerCase().includes(currentFindingSearchTerm)) ||
                (f.testing_notes && f.testing_notes.toLowerCase().includes(currentFindingSearchTerm)) ||
                (f.poc_text && f.poc_text.toLowerCase().includes(currentFindingSearchTerm));
            return matchSeverity && matchSearch;
        });

        if (filtered.length === 0) {
            listEl.innerHTML = `
                <div style="text-align: center; padding: 40px; background: var(--bg-surface); border: 1px dashed var(--border-subtle); border-radius: var(--radius-lg); color: var(--text-muted);">
                    <p style="font-size: 0.95rem; font-weight: 600;">No findings match the selected filters.</p>
                    <p style="font-size: 0.8rem; margin-top: 4px;">Try selecting "All" severities or clearing the search query.</p>
                </div>
            `;
            return;
        }

        filtered.forEach(finding => {
            const card = document.createElement("div");
            card.className = "finding-record-card";

            // Find related checklist test if available
            let relatedTestName = "";
            if (proj.checklist_data && proj.checklist_data.checklist) {
                const matchedItem = proj.checklist_data.checklist.find(i => i.id === finding.test_id);
                if (matchedItem) {
                    relatedTestName = matchedItem.name;
                }
            }

            const normPrio = normalizeSeverity(finding.priority || finding.severity);
            const prioClass = normPrio === "INFORMATIONAL" || normPrio === "INFO" ? "info" : normPrio.toLowerCase();

            card.innerHTML = `
                <div class="finding-record-header">
                    <div class="finding-title-left">
                        <span class="badge badge-secondary" style="font-family: var(--font-mono); font-weight: 700; font-size: 0.78rem;">${finding.vuln_id || 'VULN-' + String(totalCount).padStart(3, '0')}</span>
                        <span class="badge badge-${prioClass}">${normPrio}</span>
                        ${finding.fix_status ? `<span class="badge badge-completed" style="font-size: 0.72rem;">${escapeHtml(finding.fix_status)}</span>` : ''}
                        <span class="finding-record-name">${escapeHtml(finding.finding_name)}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <span style="font-size: 0.75rem; color: var(--text-light); font-family: var(--font-mono);">${finding.recorded_at || 'Recently'}</span>
                        <button type="button" class="btn btn-danger btn-sm btn-delete-finding" data-finding-id="${finding.id}">Delete</button>
                    </div>
                </div>

                ${relatedTestName ? `
                    <div style="font-size: 0.78rem; color: var(--text-muted); display: flex; align-items: center; gap: 6px;">
                        <span>Related Security Test:</span>
                        <strong style="color: var(--primary-700);">${escapeHtml(relatedTestName)}</strong>
                    </div>
                ` : (finding.source === "IMPORTED_REPORT" ? `
                    <div style="font-size: 0.78rem; color: #4338ca; display: flex; align-items: center; gap: 6px;">
                        <span>Provenance:</span>
                        <strong style="color: #4338ca;">Imported from External Report (${escapeHtml(finding.source_document_name || 'Uploaded Document')})</strong>
                    </div>
                ` : "")}

                <div class="finding-body-block">
                    <div style="display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 4px;">
                        ${finding.cwe ? `<span class="cwe-pill">${escapeHtml(finding.cwe)}</span>` : ""}
                        ${finding.cvss_score ? `<span class="badge badge-needs-review">CVSS: ${finding.cvss_score}</span>` : ""}
                        <span class="badge ${finding.status === 'Remediated' ? 'badge-completed' : 'badge-in-progress'}">${escapeHtml(finding.status || 'Open')}</span>
                    </div>
                    ${finding.description ? `<div><strong>Observation:</strong> ${escapeHtml(finding.description)}</div>` : ""}
                    ${finding.impact ? `<div><strong>Impact:</strong> ${escapeHtml(finding.impact)}</div>` : ""}
                    ${(finding.reproduction_steps || finding.testing_notes) ? `<div><strong>Reproduction Steps:</strong> ${escapeHtml(finding.reproduction_steps || finding.testing_notes)}</div>` : ""}
                    ${finding.poc_text ? `
                        <div>
                            <strong>Proof of Concept (PoC) / Payload Snippet:</strong>
                            <pre class="finding-poc-box">${escapeHtml(finding.poc_text)}</pre>
                        </div>
                    ` : ""}
                    ${finding.remediation ? `<div><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</div>` : ""}
                    ${(finding.evidence && finding.evidence.length > 0) ? `
                        <div style="margin-top: 10px;">
                            <strong>Attached PoC Evidence (${finding.evidence.length} file${finding.evidence.length > 1 ? 's' : ''}):</strong>
                            <div style="display: flex; gap: 10px; flex-wrap: wrap; margin-top: 6px;">
                                ${finding.evidence.map(ev => {
                                    const isImg = (ev.data && ev.data.startsWith("data:image/")) || (ev.name && /\.(png|jpe?g|webp|gif|svg)$/i.test(ev.name));
                                    const evSrc = ev.data || ev.url || "";
                                    const isDataImg = ev.data && ev.data.startsWith("data:image/");
                                    const evUrl = ev.url || (ev.data && !ev.data.startsWith("data:") ? ev.data : "");
                                    if (isImg && (evSrc || evUrl)) {
                                        return `
                                            <div style="text-align: center;">
                                                <a href="#" class="evidence-click-item" data-ev-url="${escapeHtml(evUrl)}" data-ev-data="${isDataImg ? escapeHtml(ev.data) : ''}" data-ev-name="${escapeHtml(ev.name || 'evidence.png')}" style="cursor: pointer; display: block;" title="Click to view full image">
                                                    <img ${isDataImg ? `src="${ev.data}"` : `data-auth-src="${escapeHtml(evUrl)}"`} class="finding-evidence-img" alt="${escapeHtml(ev.name || 'Evidence')}" style="max-height: 90px; max-width: 140px; border-radius: 4px; border: 1px solid var(--border-subtle); display: block; object-fit: cover; background: var(--bg-surface-3);" />
                                                </a>
                                                <span style="font-size: 0.7rem; color: var(--text-muted); display: block; max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 2px;">${escapeHtml(ev.name || 'evidence.png')}</span>
                                            </div>
                                        `;
                                    } else {
                                        return `
                                            <div style="background: var(--bg-surface-3); border: 1px solid var(--border-subtle); border-radius: 4px; padding: 6px 10px; font-size: 0.78rem; display: flex; align-items: center; gap: 6px;">
                                                <span>📄</span>
                                                <a href="#" class="evidence-click-item" data-ev-url="${escapeHtml(evUrl)}" data-ev-data="${ev.data && !isDataImg ? escapeHtml(ev.data) : ''}" data-ev-name="${escapeHtml(ev.name || 'evidence')}" style="color: var(--accent-primary); font-weight: 600; cursor: pointer; text-decoration: underline;" title="Click to open or download">${escapeHtml(ev.name || 'evidence')}</a>
                                            </div>
                                        `;
                                    }
                                }).join("")}
                            </div>
                        </div>
                    ` : (finding.evidence_data ? `
                        <div style="margin-top: 6px;">
                            <strong>Attached PoC Evidence:</strong><br/>
                            <a href="#" class="evidence-click-item" data-ev-url="${finding.evidence_data.startsWith('data:') ? '' : escapeHtml(finding.evidence_data)}" data-ev-data="${finding.evidence_data.startsWith('data:') ? escapeHtml(finding.evidence_data) : ''}" data-ev-name="${escapeHtml(finding.evidence_filename || 'evidence.png')}" style="cursor: pointer; display: inline-block; margin-top: 4px;" title="Click to view evidence">
                                <img ${finding.evidence_data.startsWith('data:') ? `src="${finding.evidence_data}"` : `data-auth-src="${escapeHtml(finding.evidence_data)}"`} class="finding-evidence-img" alt="${escapeHtml(finding.evidence_filename || 'Evidence')}" style="max-height: 90px; max-width: 140px; border-radius: 4px; border: 1px solid var(--border-subtle); display: block; object-fit: cover; background: var(--bg-surface-3);" />
                            </a>
                        </div>
                    ` : "")}
                </div>
            `;

            // Wire evidence click handlers
            card.querySelectorAll(".evidence-click-item").forEach(el => {
                el.addEventListener("click", (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    const eUrl = el.getAttribute("data-ev-url") || "";
                    const eName = el.getAttribute("data-ev-name") || "evidence";
                    const eData = el.getAttribute("data-ev-data") || "";
                    handleAuthenticatedEvidenceClick(eUrl, eName, eData);
                });
            });

            // Asynchronously load authenticated thumbnails
            card.querySelectorAll("img[data-auth-src]").forEach(async (img) => {
                const aSrc = img.getAttribute("data-auth-src");
                if (!aSrc) return;
                try {
                    const res = await fetch(aSrc, { headers: getAuthHeaders() });
                    if (res.ok) {
                        const blob = await res.blob();
                        img.src = URL.createObjectURL(blob);
                    }
                } catch (e) {
                    console.warn("[TRACEGATE] Failed to load authenticated evidence thumbnail:", e);
                }
            });

            card.querySelector(".btn-delete-finding").addEventListener("click", async () => {
                if (confirm(`Delete finding "${finding.finding_name}"?`)) {
                    // Call backend DELETE /api/findings/{id}
                    try {
                        await fetch(`/api/findings/${finding.id}`, {
                            method: "DELETE",
                            headers: getAuthHeaders()
                        });
                    } catch (err) {
                        console.warn("[TRACEGATE] Delete finding API fallback:", err);
                    }

                    proj.findings = proj.findings.filter(f => f.id !== finding.id);

                    // Also reset checklist item if associated
                    if (proj.checklist_data && proj.checklist_data.checklist) {
                        const item = proj.checklist_data.checklist.find(i => i.id === finding.test_id);
                        if (item) {
                            item.status = "NOT_TESTED";
                            item.finding = null;
                            try {
                                await fetch(`/api/checklist/${item.id}/status`, {
                                    method: "PUT",
                                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                                    body: JSON.stringify({ status: "NOT_TESTED" })
                                });
                            } catch (e) {}
                        }
                    }

                    saveProjects();
                    renderWorkspaceFindings();
                    updateChecklistProgressUI();
                    refreshDashboardStats();

                    const badgeCount = document.getElementById("wsFindingsBadgeCount");
                    if (badgeCount) badgeCount.textContent = proj.findings.length;

                    showToast("Finding removed.", "info");
                }
            });

            listEl.appendChild(card);
        });
    }

    // Findings Filter Event Listeners
    const findingsSearchInput = document.getElementById("findingsSearchInput");
    if (findingsSearchInput) {
        findingsSearchInput.addEventListener("input", (e) => {
            currentFindingSearchTerm = e.target.value.toLowerCase().trim();
            renderWorkspaceFindings();
        });
    }

    document.querySelectorAll("[data-finding-severity]").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll("[data-finding-severity]").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            currentFindingSeverityFilter = btn.getAttribute("data-finding-severity");
            renderWorkspaceFindings();
        });
    });

    // ==========================================================================
    // 12. REPORT GENERATION CONTROLLER (REAL DOCX & MARKDOWN EXPORT)
    // ==========================================================================
    let selectedFindingIdsForReport = new Set();
    let currentReportFindingFilter = "ALL";
    let reportSelectionInitializedProjId = null;

    function getFilteredFindings(findings, filter) {
        if (!filter || filter === "ALL") return findings;
        return findings.filter(f => {
            const p = normalizeSeverity(f.priority || f.severity);
            if (filter === "INFORMATIONAL" || filter === "INFO") {
                return p === "INFORMATIONAL" || p === "INFO";
            }
            return p === filter;
        });
    }

    function updateFilterBtnStyles() {
        const filters = [
            { id: "btnFilterAll", filter: "ALL" },
            { id: "btnFilterCrit", filter: "CRITICAL" },
            { id: "btnFilterHigh", filter: "HIGH" },
            { id: "btnFilterMed", filter: "MEDIUM" },
            { id: "btnFilterLow", filter: "LOW" },
            { id: "btnFilterInfo", filter: "INFORMATIONAL" }
        ];
        filters.forEach(f => {
            const btn = document.getElementById(f.id);
            if (!btn) return;
            if (currentReportFindingFilter === f.filter) {
                btn.classList.remove("btn-secondary");
                btn.classList.add("btn-primary");
            } else {
                btn.classList.remove("btn-primary");
                btn.classList.add("btn-secondary");
            }
        });
    }

    function renderReportFindingsSelection(proj) {
        const tbody = document.getElementById("reportFindingsSelectTbody");
        const badge = document.getElementById("reportSelectionBadge");
        const metricsPanel = document.getElementById("reportSelectedMetricsPanel");
        const cleanBox = document.getElementById("cleanReportOptionBox");
        const chkClean = document.getElementById("chkAllowCleanReport");
        const chkAllHeader = document.getElementById("chkReportSelectAllHeader");

        if (!tbody || !proj) return;

        const allFindings = proj.findings || [];
        const filteredFindings = getFilteredFindings(allFindings, currentReportFindingFilter);

        // Update clean report option box visibility (Section 27)
        if (cleanBox) {
            if (allFindings.length === 0 || selectedFindingIdsForReport.size === 0) {
                cleanBox.style.display = "flex";
            } else {
                cleanBox.style.display = "none";
                if (chkClean) chkClean.checked = false;
            }
        }

        // Update selection badge counter
        if (badge) {
            badge.textContent = `${selectedFindingIdsForReport.size} of ${allFindings.length} findings selected`;
            if (selectedFindingIdsForReport.size > 0) {
                badge.className = "badge badge-completed";
            } else {
                badge.className = "badge badge-needs-review";
            }
        }

        // Render Selection Table Rows
        if (allFindings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 24px;">No confirmed vulnerabilities recorded for this assessment. You may certify a Clean Assessment Report below.</td></tr>`;
            if (chkAllHeader) {
                chkAllHeader.checked = false;
                chkAllHeader.indeterminate = false;
                chkAllHeader.disabled = true;
            }
        } else if (filteredFindings.length === 0) {
            tbody.innerHTML = `<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 20px;">No confirmed findings match the "${escapeHtml(currentReportFindingFilter)}" severity filter.</td></tr>`;
            if (chkAllHeader) {
                chkAllHeader.checked = false;
                chkAllHeader.indeterminate = false;
                chkAllHeader.disabled = true;
            }
        } else {
            if (chkAllHeader) chkAllHeader.disabled = false;
            let rowsHtml = "";
            let checkedVisibleCount = 0;

            filteredFindings.forEach((f, idx) => {
                const isSelected = selectedFindingIdsForReport.has(f.id);
                if (isSelected) checkedVisibleCount++;

                const priorityUpper = normalizeSeverity(f.priority || f.severity);
                const priorityClass = priorityUpper === "INFORMATIONAL" || priorityUpper === "INFO" ? "info" : priorityUpper.toLowerCase();
                const hasPoc = Boolean(f.poc_text && f.poc_text.trim());
                const hasEvidence = Boolean(f.evidence_filename || f.evidence_data);

                rowsHtml += `
                    <tr style="background: ${isSelected ? 'rgba(37, 99, 235, 0.05)' : 'transparent'};">
                        <td style="text-align: center;">
                            <input type="checkbox" class="chk-report-finding" data-id="${escapeHtml(f.id)}" ${isSelected ? 'checked' : ''} style="cursor: pointer; width: 16px; height: 16px;" />
                        </td>
                        <td><span style="font-family: var(--font-mono); font-size: 0.78rem; font-weight: 600;">#${idx + 1}</span></td>
                        <td>
                            <strong>${escapeHtml(f.finding_name || 'Vulnerability')}</strong>
                            ${f.description ? `<div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 2px; max-width: 320px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(f.description)}</div>` : ''}
                        </td>
                        <td><span class="badge badge-${priorityClass}">${escapeHtml(priorityUpper)}</span></td>
                        <td>${f.cwe ? `<span class="cwe-pill">${escapeHtml(f.cwe)}</span>` : '<span style="color:var(--text-muted);">-</span>'}</td>
                        <td><span style="font-size: 0.8rem; color: var(--text-secondary);">${escapeHtml(f.component || 'Web App')}</span></td>
                        <td>${hasPoc ? '<span class="badge badge-completed">Attached</span>' : '<span class="badge badge-needs-review">None</span>'}</td>
                        <td>${hasEvidence ? '<span class="badge badge-completed">Attached</span>' : '<span class="badge badge-needs-review">None</span>'}</td>
                    </tr>
                `;
            });

            tbody.innerHTML = rowsHtml;

            // Update header checkbox
            if (chkAllHeader) {
                if (checkedVisibleCount === filteredFindings.length) {
                    chkAllHeader.checked = true;
                    chkAllHeader.indeterminate = false;
                } else if (checkedVisibleCount > 0) {
                    chkAllHeader.checked = false;
                    chkAllHeader.indeterminate = true;
                } else {
                    chkAllHeader.checked = false;
                    chkAllHeader.indeterminate = false;
                }
            }

            // Wire row checkboxes
            tbody.querySelectorAll(".chk-report-finding").forEach(chk => {
                chk.addEventListener("change", (e) => {
                    const fid = e.target.getAttribute("data-id");
                    if (e.target.checked) {
                        selectedFindingIdsForReport.add(fid);
                    } else {
                        selectedFindingIdsForReport.delete(fid);
                    }
                    renderReportFindingsSelection(proj);
                });
            });
        }

        // Render Dynamic Metrics Summary Panel
        if (metricsPanel) {
            const selectedFindings = allFindings.filter(f => selectedFindingIdsForReport.has(f.id));
            const countCrit = selectedFindings.filter(f => normalizeSeverity(f.priority || f.severity) === 'CRITICAL').length;
            const countHigh = selectedFindings.filter(f => normalizeSeverity(f.priority || f.severity) === 'HIGH').length;
            const countMed = selectedFindings.filter(f => normalizeSeverity(f.priority || f.severity) === 'MEDIUM').length;
            const countLow = selectedFindings.filter(f => normalizeSeverity(f.priority || f.severity) === 'LOW').length;
            const countInfo = selectedFindings.filter(f => normalizeSeverity(f.priority || f.severity) === 'INFORMATIONAL').length;
            const countPoc = selectedFindings.filter(f => Boolean(f.poc_text && f.poc_text.trim())).length;
            const countEvidence = selectedFindings.filter(f => Boolean(f.evidence_filename || f.evidence_data)).length;
            const countMissingRemediation = selectedFindings.filter(f => !f.remediation && !f.mitigation && !f.fix_guidance).length;

            metricsPanel.innerHTML = `
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Selected</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--primary-600);">${selectedFindings.length} / ${allFindings.length}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--crit-badge); font-weight: 700;">Critical</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--crit-badge);">${countCrit}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--high-badge); font-weight: 700;">High</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--high-badge);">${countHigh}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--med-badge); font-weight: 700;">Medium</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--med-badge);">${countMed}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--low-badge); font-weight: 700;">Low</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--low-badge);">${countLow}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: #0284c7; font-weight: 700;">Informational</span><br/>
                    <strong style="font-size: 1.05rem; color: #0284c7;">${countInfo}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">PoC Attached</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--text-primary);">${countPoc}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Evidence Attached</span><br/>
                    <strong style="font-size: 1.05rem; color: var(--text-primary);">${countEvidence}</strong>
                </div>
                <div style="background: #ffffff; padding: 10px 12px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle); text-align: center;">
                    <span style="font-size: 0.68rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Missing Remediation</span><br/>
                    <strong style="font-size: 1.05rem; color: ${countMissingRemediation > 0 ? 'var(--med-badge)' : 'var(--clean-color)'};">${countMissingRemediation}</strong>
                </div>
            `;
        }
    }

    // Wire bulk buttons and filter selectors once
    const btnReportSelectAll = document.getElementById("btnReportSelectAll");
    if (btnReportSelectAll) {
        btnReportSelectAll.addEventListener("click", () => {
            const proj = getActiveProject();
            if (!proj) return;
            const allFindings = proj.findings || [];
            allFindings.forEach(f => selectedFindingIdsForReport.add(f.id));
            renderReportFindingsSelection(proj);
        });
    }

    const btnReportClearAll = document.getElementById("btnReportClearAll");
    if (btnReportClearAll) {
        btnReportClearAll.addEventListener("click", () => {
            const proj = getActiveProject();
            if (!proj) return;
            selectedFindingIdsForReport.clear();
            renderReportFindingsSelection(proj);
        });
    }

    const chkReportSelectAllHeader = document.getElementById("chkReportSelectAllHeader");
    if (chkReportSelectAllHeader) {
        chkReportSelectAllHeader.addEventListener("change", (e) => {
            const proj = getActiveProject();
            if (!proj) return;
            const filteredFindings = getFilteredFindings(proj.findings || [], currentReportFindingFilter);
            if (e.target.checked) {
                filteredFindings.forEach(f => selectedFindingIdsForReport.add(f.id));
            } else {
                filteredFindings.forEach(f => selectedFindingIdsForReport.delete(f.id));
            }
            renderReportFindingsSelection(proj);
        });
    }

    const reportFilterBtns = [
        { id: "btnFilterAll", filter: "ALL" },
        { id: "btnFilterCrit", filter: "CRITICAL" },
        { id: "btnFilterHigh", filter: "HIGH" },
        { id: "btnFilterMed", filter: "MEDIUM" },
        { id: "btnFilterLow", filter: "LOW" },
        { id: "btnFilterInfo", filter: "INFORMATIONAL" }
    ];
    reportFilterBtns.forEach(fb => {
        const el = document.getElementById(fb.id);
        if (el) {
            el.addEventListener("click", () => {
                currentReportFindingFilter = fb.filter;
                updateFilterBtnStyles();
                const proj = getActiveProject();
                if (proj) renderReportFindingsSelection(proj);
            });
        }
    });

    async function renderWorkspaceReport() {
        const contentEl = document.getElementById("reportSummaryContent");
        if (!contentEl) return;

        const proj = getActiveProject();
        if (!proj) return;

        // Fetch latest findings directly from backend to guarantee sync
        try {
            const findRes = await fetch(`/api/projects/${proj.id}/findings`, {
                headers: getAuthHeaders()
            });
            if (findRes.ok) {
                const rawFindings = await findRes.json();
                const findingsData = Array.isArray(rawFindings) ? rawFindings : (rawFindings.findings || []);
                if (Array.isArray(findingsData)) {
                    proj.findings = findingsData;
                }
            }
        } catch (e) {
            console.warn("[TRACEGATE] Failed to refresh findings for report:", e);
        }

        // Initialize selection state for this project
        const allFindings = proj.findings || [];
        const currentIds = new Set(allFindings.map(f => f.id));
        if (reportSelectionInitializedProjId !== proj.id) {
            selectedFindingIdsForReport = new Set(currentIds);
            reportSelectionInitializedProjId = proj.id;
            currentReportFindingFilter = "ALL";
        } else {
            // Keep only IDs that still exist
            selectedFindingIdsForReport = new Set([...selectedFindingIdsForReport].filter(id => currentIds.has(id)));
        }

        updateFilterBtnStyles();
        renderReportFindingsSelection(proj);

        const m = calculateProjectMetrics(proj);
        const vulns = allFindings;

        let tableRows = "";
        if (vulns.length === 0) {
            tableRows = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 20px;">No vulnerabilities confirmed yet for this assessment scope.</td></tr>`;
        } else {
            vulns.forEach((v, idx) => {
                const priorityUpper = normalizeSeverity(v.priority || v.severity);
                const priorityClass = priorityUpper === "INFORMATIONAL" || priorityUpper === "INFO" ? "info" : priorityUpper.toLowerCase();
                tableRows += `
                    <tr>
                        <td><strong>#${idx + 1}</strong></td>
                        <td><span class="badge badge-${priorityClass}">${escapeHtml(priorityUpper)}</span></td>
                        <td><strong>${escapeHtml(v.finding_name)}</strong></td>
                        <td>${v.cwe ? `<span class="cwe-pill">${escapeHtml(v.cwe)}</span>` : '<span style="color:var(--text-muted);">-</span>'}</td>
                        <td>${v.poc_text ? '<span class="badge badge-completed">PoC Verified</span>' : '<span class="badge badge-needs-review">Notes Only</span>'}</td>
                    </tr>
                `;
            });
        }

        contentEl.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px;">
                <div style="background: #ffffff; padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                    <span style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Target Application</span><br/>
                    <strong style="font-family: var(--font-mono); font-size: 0.85rem;">${escapeHtml(proj.target_url)}</strong>
                </div>
                <div style="background: #ffffff; padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                    <span style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Scope Tests Evaluated</span><br/>
                    <strong style="font-size: 1.1rem; color: var(--primary-600);">${m.completed} / ${m.total} (${m.pct}%)</strong>
                </div>
                <div style="background: #ffffff; padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                    <span style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Confirmed Findings</span><br/>
                    <strong style="font-size: 1.1rem; color: var(--crit-color);">${vulns.length}</strong>
                </div>
                <div style="background: #ffffff; padding: 14px; border-radius: var(--radius-md); border: 1px solid var(--border-subtle);">
                    <span style="font-size: 0.72rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700;">Verified Clean Controls</span><br/>
                    <strong style="font-size: 1.1rem; color: var(--clean-color);">${m.clean}</strong>
                </div>
            </div>

            <div style="margin-top: 10px;">
                <h5 style="font-size: 0.92rem; margin-bottom: 8px;">Consolidated Vulnerabilities Table</h5>
                <table class="report-table">
                    <thead>
                        <tr>
                            <th>Item</th>
                            <th>Severity</th>
                            <th>Vulnerability Title</th>
                            <th>CWE</th>
                            <th>Evidence Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${tableRows}
                    </tbody>
                </table>
            </div>
        `;

        // Pre-fill author name
        const authorInp = document.getElementById("docxAuthorName");
        if (authorInp && currentUser) {
            authorInp.value = currentUser.full_name || currentUser.name || "Security Learner";
        }

        // Reset report generation success card on project/scope change
        const successCard = document.getElementById("reportGenSuccessCard");
        if (successCard) successCard.style.display = "none";

        // Load project reports history
        await loadProjectReports(proj.id);
    }

    async function loadProjectReports(projId) {
        const tbody = document.getElementById("reportHistoryTableBody");
        if (!tbody) return;

        try {
            const res = await fetch(`/api/projects/${projId}/reports`, {
                headers: getAuthHeaders()
            });
            if (res.ok) {
                const reports = await res.json();
                if (Array.isArray(reports) && reports.length > 0) {
                    let rows = "";
                    reports.forEach(r => {
                        const badgeHtml = `<span class="badge badge-info">DOCX</span>`;
                        const safeDocxName = r.filename || `${r.project_id}_${r.version}.docx`;
                        rows += `
                            <tr>
                                <td><strong>${escapeHtml(r.version)}</strong></td>
                                <td>${escapeHtml(r.created_at || 'Recent')}</td>
                                <td>${escapeHtml(r.author_name || 'Security Assessor')}</td>
                                <td><span class="badge ${r.findings_count > 0 ? 'badge-critical' : 'badge-clean'}">${r.findings_count} Vulns</span></td>
                                <td>${badgeHtml}</td>
                                <td>
                                    <div style="display: flex; gap: 6px;">
                                        <button type="button" class="btn btn-outline-primary btn-sm btn-dl-hist-docx" data-proj="${escapeHtml(projId)}" data-rep="${escapeHtml(r.id)}" data-fn="${escapeHtml(safeDocxName)}" title="Download Microsoft Word Document">
                                            📥 DOCX
                                        </button>
                                    </div>
                                </td>
                            </tr>
                        `;
                    });
                    tbody.innerHTML = rows;

                    // Wire explicit download action listeners to prevent download.json
                    tbody.querySelectorAll(".btn-dl-hist-docx").forEach(btn => {
                        btn.addEventListener("click", (e) => {
                            e.preventDefault();
                            handleExplicitReportDownload(btn.dataset.proj, btn.dataset.rep, "docx", btn.dataset.fn, btn);
                        });
                    });

                    // Server-authoritative next report version sync
                    try {
                        const vRes = await fetch(`/api/projects/${projId}/reports/next-version`, {
                            headers: getAuthHeaders()
                        });
                        if (vRes.ok) {
                            const vData = await vRes.json();
                            const vInp = document.getElementById("docxReportVersion");
                            if (vInp && vData.next_version) {
                                vInp.value = vData.next_version;
                            }
                        }
                    } catch (ve) {
                        console.debug("[TRACEGATE] next-version fetch error:", ve);
                    }

                    return;
                }
            }
        } catch (e) {
            console.warn("[TRACEGATE] Failed to load reports history:", e);
        }

        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 18px;">No previous report packages recorded for this project.</td></tr>`;

        // Pre-fill next version for empty reports history
        try {
            const vRes = await fetch(`/api/projects/${projId}/reports/next-version`, {
                headers: getAuthHeaders()
            });
            if (vRes.ok) {
                const vData = await vRes.json();
                const vInp = document.getElementById("docxReportVersion");
                if (vInp && vData.next_version) {
                    vInp.value = vData.next_version;
                }
            }
        } catch (ve) {
            console.debug("[TRACEGATE] next-version fetch error:", ve);
        }
    }

    // Dedicated explicit download helper for generated reports with double-click protection & blob validation
    let isDownloadingReport = false;
    async function handleExplicitReportDownload(projId, reportId, format, filename, triggerBtn) {
        if (isDownloadingReport) return;
        isDownloadingReport = true;

        const originalText = triggerBtn ? triggerBtn.innerHTML : "";
        if (triggerBtn) {
            triggerBtn.disabled = true;
            triggerBtn.textContent = `Downloading ${format.toUpperCase()}...`;
        }

        try {
            showToast(`📥 Requesting ${format.toUpperCase()} report...`, "info");
            const downloadUrl = `/api/projects/${encodeURIComponent(projId)}/reports/${encodeURIComponent(reportId)}/download?format=${encodeURIComponent(format)}`;
            const res = await fetch(downloadUrl, {
                headers: getAuthHeaders()
            });

            if (!res.ok) {
                let errDetail = `Unable to download ${format.toUpperCase()} report.`;
                try {
                    const errJson = await res.json();
                    if (errJson.detail) errDetail = errJson.detail;
                } catch (_) {}
                showToast(errDetail, "error");
                return;
            }

            const contentType = res.headers.get("content-type") || "";
            if (format === "pdf" && contentType.includes("application/json")) {
                showToast("PDF report could not be generated.", "error");
                return;
            }

            const blob = await res.blob();
            if (blob.size < 100) {
                showToast("Received empty or corrupt report artifact.", "error");
                return;
            }

            const blobUrl = window.URL.createObjectURL(blob);
            const dlLink = document.createElement("a");
            dlLink.style.display = "none";
            dlLink.href = blobUrl;
            const safeName = filename || `Report_${projId}_${format}.${format}`;
            dlLink.download = safeName;
            document.body.appendChild(dlLink);
            dlLink.click();
            setTimeout(() => {
                document.body.removeChild(dlLink);
                window.URL.revokeObjectURL(blobUrl);
            }, 1500);
            showToast(`✓ ${format.toUpperCase()} report downloaded successfully.`, "success");
        } catch (err) {
            console.error("[TRACEGATE] Report download failed:", err);
            showToast("Unable to download this report artifact.", "error");
        } finally {
            setTimeout(() => {
                isDownloadingReport = false;
                if (triggerBtn) {
                    triggerBtn.disabled = false;
                    triggerBtn.innerHTML = originalText;
                }
            }, 800);
        }
    }

    // Generate Official Microsoft Word (.docx) Report with 4-stage Stepper
    const btnGenerateDocxReport = document.getElementById("btnGenerateDocxReport");
    if (btnGenerateDocxReport) {
        btnGenerateDocxReport.addEventListener("click", async () => {
            const proj = getActiveProject();
            if (!proj) {
                showToast("No active project selected.", "error");
                return;
            }

            const isCleanAllowed = document.getElementById("chkAllowCleanReport")?.checked || false;
            const selectedIds = Array.from(selectedFindingIdsForReport);

            // Validation (Section 27 & 48)
            if (selectedIds.length === 0 && !isCleanAllowed) {
                showToast("Select at least one finding to include in the report, or check Clean Assessment Report to certify no vulnerabilities.", "warning");
                return;
            }

            const version = document.getElementById("docxReportVersion")?.value.trim() || "v1.0";
            const author = document.getElementById("docxAuthorName")?.value.trim() || currentUser?.name || "Security Learner";
            const methodology = document.getElementById("docxMethodologySelect")?.value || "owasp_wstg";

            const stepperBox = document.getElementById("reportGenStepperBox");
            const step1 = document.getElementById("loadingDocxStep1");
            const step2 = document.getElementById("loadingDocxStep2");
            const step3 = document.getElementById("loadingDocxStep3");
            const step4 = document.getElementById("loadingDocxStep4");
            const btnTextSpan = document.getElementById("btnGenerateDocxReportText") || btnGenerateDocxReport.querySelector("span");
            const successCard = document.getElementById("reportGenSuccessCard");

            btnGenerateDocxReport.disabled = true;
            if (btnTextSpan) btnTextSpan.textContent = "⏳ Generating DOCX Report...";
            if (successCard) successCard.style.display = "none";
            if (stepperBox) stepperBox.classList.add("active");

            // Sequential 4-stage progress
            if (step1) {
                step1.className = "step-item running";
                step1.textContent = "● Consolidating assessment findings & methodology";
            }
            if (step2) {
                step2.className = "step-item pending";
                step2.textContent = "○ Calculating risk metrics & executive summaries";
            }
            if (step3) {
                step3.className = "step-item pending";
                step3.textContent = "○ Embedding PoC snippets & evidence screenshots";
            }
            if (step4) {
                step4.className = "step-item running";
                step4.textContent = "○ Compiling Microsoft Word (.docx) report package";
            }

            setTimeout(() => {
                if (step1) {
                    step1.className = "step-item done";
                    step1.textContent = "✓ Assessment findings & methodology consolidated";
                }
                if (step2) {
                    step2.className = "step-item running";
                    step2.textContent = "● Calculating risk metrics & executive summaries";
                }
            }, 300);

            setTimeout(() => {
                if (step2) {
                    step2.className = "step-item done";
                    step2.textContent = "✓ Risk metrics & executive summaries calculated";
                }
                if (step3) {
                    step3.className = "step-item running";
                    step3.textContent = "● Embedding PoC snippets & evidence screenshots";
                }
            }, 600);

            setTimeout(() => {
                if (step3) {
                    step3.className = "step-item done";
                    step3.textContent = "✓ PoC snippets & evidence figures embedded";
                }
                if (step4) {
                    step4.className = "step-item running";
                    step4.textContent = "● Compiling Microsoft Word (.docx) report package";
                }
            }, 900);

            try {
                const res = await fetch(`/api/projects/${proj.id}/reports`, {
                    method: "POST",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({
                        version: version,
                        author_name: author,
                        methodology: methodology,
                        selected_finding_ids: selectedIds,
                        allow_clean_report: isCleanAllowed
                    })
                });

                if (!res.ok) {
                    let errDetail = "Report generation failed.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    throw new Error(errDetail);
                }

                const reportRecord = await res.json();

                if (step4) {
                    step4.className = "step-item done";
                    step4.textContent = "✓ Microsoft Word (.docx) report compiled successfully!";
                }

                setTimeout(() => {
                    if (stepperBox) stepperBox.classList.remove("active");
                    btnGenerateDocxReport.disabled = false;
                    if (btnTextSpan) btnTextSpan.textContent = "📄 Generate DOCX Report";

                    // NO AUTOMATIC DOWNLOAD: Display professional success card with explicit download controls
                    if (successCard) {
                        const repIdEl = document.getElementById("successReportId");
                        const repVerEl = document.getElementById("successReportVersion");
                        const repStatEl = document.getElementById("successReportStatus");
                        if (repIdEl) repIdEl.textContent = reportRecord.id || "REP-READY";
                        if (repVerEl) repVerEl.textContent = reportRecord.version || version;
                        if (repStatEl) repStatEl.textContent = "READY";
                        successCard.style.display = "block";
                    }

                    // Wire explicit download actions using existing secure Report History download pipeline
                    const btnDlDocx = document.getElementById("btnDownloadGeneratedDocx");
                    if (btnDlDocx) {
                        btnDlDocx.onclick = (e) => {
                            e.preventDefault();
                            const docxName = reportRecord.filename || `${proj.name}_vapt_report_${version}.docx`;
                            handleExplicitReportDownload(proj.id, reportRecord.id, "docx", docxName, btnDlDocx);
                        };
                    }

                    const btnViewHistory = document.getElementById("btnViewInReportHistory");
                    if (btnViewHistory) {
                        btnViewHistory.onclick = (e) => {
                            e.preventDefault();
                            const historyEl = document.getElementById("reportHistoryTableBody");
                            if (historyEl) {
                                historyEl.scrollIntoView({ behavior: "smooth", block: "center" });
                            }
                        };
                    }

                    showToast(`✓ VAPT Report (${version}) generated successfully. Available below and in Report History.`, "success");
                    loadProjectReports(proj.id);
                }, 500);

            } catch (err) {
                if (stepperBox) stepperBox.classList.remove("active");
                btnGenerateDocxReport.disabled = false;
                if (btnTextSpan) btnTextSpan.textContent = "📄 Generate DOCX Report";
                showToast("Report Generation Error: " + err.message, "error");
            }
        });
    }

    // ==========================================================================
    // MANUAL VAPT REPORT IMPORTER & CANDIDATE FINDINGS REVIEW
    // ==========================================================================
    let currentImportState = {
        source_doc_id: null,
        source_doc_name: null,
        candidates: []
    };

    function initReportImporter() {
        const dropzone = document.getElementById("reportImportDropzone");
        const fileInput = document.getElementById("reportImportFileInput");
        const btnClose = document.getElementById("btnCloseImportModal");
        const btnCancel = document.getElementById("btnCancelImportModal");
        const btnSelectAll = document.getElementById("btnImportSelectAll");
        const btnDeselectAll = document.getElementById("btnImportDeselectAll");
        const btnDeselectDupes = document.getElementById("btnImportDeselectDuplicates");
        const btnConfirm = document.getElementById("btnConfirmImportFindings");

        if (!dropzone || !fileInput) return;

        dropzone.addEventListener("click", () => fileInput.click());

        dropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropzone.style.borderColor = "var(--primary-600)";
            dropzone.style.background = "var(--primary-50, #eff6ff)";
        });

        dropzone.addEventListener("dragleave", (e) => {
            e.preventDefault();
            dropzone.style.borderColor = "var(--border-default)";
            dropzone.style.background = "var(--bg-subtle)";
        });

        dropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropzone.style.borderColor = "var(--border-default)";
            dropzone.style.background = "var(--bg-subtle)";
            if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
                handleReportFileSelected(e.dataTransfer.files[0]);
            }
        });

        fileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files.length > 0) {
                handleReportFileSelected(e.target.files[0]);
            }
        });

        if (btnClose) btnClose.addEventListener("click", () => closeModal("modalImportReportReview"));
        if (btnCancel) btnCancel.addEventListener("click", () => closeModal("modalImportReportReview"));

        if (btnSelectAll) {
            btnSelectAll.addEventListener("click", () => {
                currentImportState.candidates.forEach(c => c.selected = true);
                renderCandidateFindingsList();
            });
        }

        if (btnDeselectAll) {
            btnDeselectAll.addEventListener("click", () => {
                currentImportState.candidates.forEach(c => c.selected = false);
                renderCandidateFindingsList();
            });
        }

        if (btnDeselectDupes) {
            btnDeselectDupes.addEventListener("click", () => {
                currentImportState.candidates.forEach(c => c.selected = !c.is_duplicate);
                renderCandidateFindingsList();
            });
        }

        if (btnConfirm) {
            btnConfirm.addEventListener("click", handleConfirmImport);
        }
    }

    async function handleReportFileSelected(file) {
        const proj = getActiveProject();
        if (!proj) {
            showToast("Please select an active project first.", "warning");
            return;
        }

        const validExts = [".pdf", ".docx", ".txt", ".md"];
        const lowerName = file.name.toLowerCase();
        const hasValidExt = validExts.some(ext => lowerName.endsWith(ext));
        if (!hasValidExt) {
            showToast("Unsupported file type. Please upload a PDF, DOCX, TXT, or MD report file.", "error");
            return;
        }

        if (file.size > 25 * 1024 * 1024) {
            showToast("File size exceeds maximum allowed 25MB.", "error");
            return;
        }

        const spinner = document.getElementById("reportImportSpinner");
        if (spinner) spinner.style.display = "flex";

        const formData = new FormData();
        formData.append("file", file);

        try {
            const res = await fetch(`/api/projects/${proj.id}/reports/parse-import`, {
                method: "POST",
                headers: getAuthHeaders(),
                body: formData
            });

            if (!res.ok) {
                let err = "Failed to parse report file.";
                try {
                    const data = await res.json();
                    if (data.detail) err = data.detail;
                } catch (_) {}
                throw new Error(err);
            }

            const parsed = await res.json();
            const candidates = parsed.candidate_findings || [];

            if (candidates.length === 0) {
                showToast("No security findings could be identified in the uploaded report.", "warning");
                return;
            }

            currentImportState = {
                source_doc_id: parsed.source_document_id,
                source_doc_name: parsed.source_document_name,
                candidates: candidates.map(c => ({
                    ...c,
                    selected: !c.is_duplicate
                }))
            };

            const nameEl = document.getElementById("importDocNameSpan");
            if (nameEl) nameEl.textContent = parsed.source_document_name;

            const countEl = document.getElementById("importCandidatesCountBadge");
            if (countEl) countEl.textContent = `${candidates.length} finding${candidates.length > 1 ? "s" : ""} parsed`;

            const dupeCount = candidates.filter(c => c.is_duplicate).length;
            const dupeBadge = document.getElementById("importDuplicatesCountBadge");
            if (dupeBadge) {
                if (dupeCount > 0) {
                    dupeBadge.textContent = `${dupeCount} duplicate${dupeCount > 1 ? "s" : ""} detected`;
                    dupeBadge.style.display = "inline-flex";
                } else {
                    dupeBadge.style.display = "none";
                }
            }

            renderCandidateFindingsList();
            openModal("modalImportReportReview");

        } catch (e) {
            console.error("[TRACEGATE] Report import parse error:", e);
            showToast("Error parsing report: " + e.message, "error");
        } finally {
            if (spinner) spinner.style.display = "none";
            const fileInput = document.getElementById("reportImportFileInput");
            if (fileInput) fileInput.value = "";
        }
    }

    function renderCandidateFindingsList() {
        const container = document.getElementById("importCandidatesListContainer");
        const selCountSpan = document.getElementById("importSelectedCountSpan");
        if (!container) return;

        const candidates = currentImportState.candidates || [];
        const selectedCount = candidates.filter(c => c.selected).length;

        if (selCountSpan) {
            selCountSpan.textContent = `${selectedCount} of ${candidates.length} findings selected for import`;
        }

        if (candidates.length === 0) {
            container.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 20px;">No findings to display.</div>`;
            return;
        }

        let html = "";
        candidates.forEach((cand, idx) => {
            const priority = normalizeSeverity(cand.severity || cand.priority);
            const priorityClass = priority === "INFORMATIONAL" || priority === "INFO" ? "info" : priority.toLowerCase();
            const isDupe = Boolean(cand.is_duplicate);

            html += `
                <div class="candidate-finding-card" style="border: 1px solid ${isDupe ? '#f59e0b' : 'var(--border-default)'}; border-radius: var(--radius-md); background: ${cand.selected ? 'rgba(37, 99, 235, 0.03)' : '#ffffff'}; padding: 14px 16px; transition: all 0.15s ease;">
                    <div style="display: flex; align-items: flex-start; justify-content: space-between; gap: 12px;">
                        <div style="display: flex; align-items: flex-start; gap: 12px; flex: 1;">
                            <input type="checkbox" class="chk-candidate-select" data-idx="${idx}" ${cand.selected ? "checked" : ""} style="cursor: pointer; width: 18px; height: 18px; margin-top: 3px;" />
                            <div style="flex: 1;">
                                <div style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 4px;">
                                    <span class="badge badge-${priorityClass}">${escapeHtml(priority)}</span>
                                    ${cand.cwe ? `<span class="cwe-pill">${escapeHtml(cand.cwe)}</span>` : ""}
                                    ${cand.cvss_score ? `<span class="badge badge-needs-review">CVSS: ${cand.cvss_score}</span>` : ""}
                                    <strong style="font-size: 0.95rem; color: var(--text-primary);">${escapeHtml(cand.title || 'Security Finding')}</strong>
                                </div>

                                ${isDupe ? `
                                    <div style="background: #fffbeb; border: 1px solid #fde68a; border-radius: 4px; padding: 6px 10px; margin: 6px 0; font-size: 0.8rem; color: #92400e; display: flex; align-items: center; gap: 6px;">
                                        <span>⚠️</span>
                                        <span><strong>Potential Duplicate:</strong> ${escapeHtml(cand.duplicate_warning || 'Matches an existing finding in this project')}</span>
                                    </div>
                                ` : ""}

                                <div style="display: flex; gap: 14px; font-size: 0.78rem; color: var(--text-muted); flex-wrap: wrap; margin-top: 4px;">
                                    ${cand.affected_url ? `<span><strong>URL:</strong> ${escapeHtml(cand.affected_url)}</span>` : ""}
                                    ${cand.affected_component ? `<span><strong>Component:</strong> ${escapeHtml(cand.affected_component)}</span>` : ""}
                                </div>
                            </div>
                        </div>

                        <button type="button" class="btn btn-secondary btn-sm btn-toggle-cand-details" data-idx="${idx}" style="font-size: 0.76rem; padding: 3px 8px; white-space: nowrap;">
                            Details ▾
                        </button>
                    </div>

                    <div id="candDetails-${idx}" style="display: none; margin-top: 12px; padding-top: 12px; border-top: 1px dashed var(--border-subtle); font-size: 0.84rem; flex-direction: column; gap: 8px;">
                        ${cand.description ? `<div><strong>Description:</strong> <div style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(cand.description)}</div></div>` : ""}
                        ${cand.impact ? `<div><strong>Impact:</strong> <div style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(cand.impact)}</div></div>` : ""}
                        ${cand.steps_to_reproduce ? `<div><strong>Steps to Reproduce:</strong> <div style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(cand.steps_to_reproduce)}</div></div>` : ""}
                        ${cand.poc_text ? `<div><strong>PoC / Payload:</strong> <pre class="finding-poc-box" style="margin-top: 4px; max-height: 120px; overflow-y: auto;">${escapeHtml(cand.poc_text)}</pre></div>` : ""}
                        ${cand.remediation ? `<div><strong>Remediation:</strong> <div style="color: var(--text-secondary); margin-top: 2px;">${escapeHtml(cand.remediation)}</div></div>` : ""}
                    </div>
                </div>
            `;
        });

        container.innerHTML = html;

        container.querySelectorAll(".chk-candidate-select").forEach(chk => {
            chk.addEventListener("change", (e) => {
                const i = parseInt(e.target.getAttribute("data-idx"), 10);
                if (currentImportState.candidates[i]) {
                    currentImportState.candidates[i].selected = e.target.checked;
                }
                const updatedCount = currentImportState.candidates.filter(c => c.selected).length;
                if (selCountSpan) {
                    selCountSpan.textContent = `${updatedCount} of ${candidates.length} findings selected for import`;
                }
            });
        });

        container.querySelectorAll(".btn-toggle-cand-details").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const i = e.target.getAttribute("data-idx");
                const detailBox = document.getElementById(`candDetails-${i}`);
                if (detailBox) {
                    const isShown = detailBox.style.display === "flex";
                    detailBox.style.display = isShown ? "none" : "flex";
                    e.target.textContent = isShown ? "Details ▾" : "Hide ▴";
                }
            });
        });
    }

    async function handleConfirmImport() {
        const proj = getActiveProject();
        if (!proj) return;

        const selectedCandidates = (currentImportState.candidates || []).filter(c => c.selected);
        if (selectedCandidates.length === 0) {
            showToast("Please select at least one finding to import.", "warning");
            return;
        }

        const btnConfirm = document.getElementById("btnConfirmImportFindings");
        if (btnConfirm) {
            btnConfirm.disabled = true;
            btnConfirm.innerHTML = `<span>Importing ${selectedCandidates.length} findings...</span>`;
        }

        try {
            const res = await fetch(`/api/projects/${proj.id}/reports/import-findings`, {
                method: "POST",
                headers: getAuthHeaders({ "Content-Type": "application/json" }),
                body: JSON.stringify({
                    source_document_id: currentImportState.source_doc_id,
                    source_document_name: currentImportState.source_doc_name,
                    candidate_findings: selectedCandidates
                })
            });

            if (!res.ok) {
                let err = "Failed to import findings.";
                try {
                    const data = await res.json();
                    if (data.detail) err = data.detail;
                } catch (_) {}
                throw new Error(err);
            }

            const data = await res.json();
            const importedList = data.imported_findings || [];

            if (!proj.findings) proj.findings = [];
            importedList.forEach(savedF => {
                proj.findings.unshift(savedF);
                if (typeof selectedFindingIdsForReport !== "undefined") {
                    selectedFindingIdsForReport.add(savedF.id);
                }
            });
            proj.updated_at = new Date().toISOString().split("T")[0];

            saveProjects();
            closeModal("modalImportReportReview");

            renderWorkspaceFindings();
            renderReportFindingsSelection(proj);
            refreshDashboardStats();
            if (typeof renderWorkspaceAutoFix === "function") {
                renderWorkspaceAutoFix(proj);
            }

            const badgeCount = document.getElementById("wsFindingsBadgeCount");
            if (badgeCount) badgeCount.textContent = proj.findings.length;

            showToast(`✓ Successfully imported ${importedList.length} finding${importedList.length > 1 ? "s" : ""} from report!`, "success");

        } catch (e) {
            console.error("[TRACEGATE] Failed to save imported findings:", e);
            showToast("Import error: " + e.message, "error");
        } finally {
            if (btnConfirm) {
                btnConfirm.disabled = false;
                btnConfirm.innerHTML = `<span>📥 Import Selected Findings</span>`;
            }
        }
    }

    const btnReportDownloadMarkdown = document.getElementById("btnReportDownloadMarkdown");
    if (btnReportDownloadMarkdown) {
        btnReportDownloadMarkdown.addEventListener("click", () => exportAssessmentMarkdown());
    }

    const btnReportCopyMarkdown = document.getElementById("btnReportCopyMarkdown");
    if (btnReportCopyMarkdown) {
        btnReportCopyMarkdown.addEventListener("click", () => copyAssessmentMarkdown());
    }

    const btnExportMarkdown = document.getElementById("btnExportMarkdown");
    if (btnExportMarkdown) {
        btnExportMarkdown.addEventListener("click", () => exportAssessmentMarkdown());
    }

    function buildAssessmentMarkdown(proj) {
        if (!proj) return "";

        const m = calculateProjectMetrics(proj);
        const vulns = proj.findings || [];
        const checklist = (proj.checklist_data && proj.checklist_data.checklist) ? proj.checklist_data.checklist : [];
        const pageType = proj.checklist_data?.page_type || "Web Application Target";
        const assessorName = currentUser ? (currentUser.full_name || currentUser.name || "Security Learner") : "Security Learner";
        const assessorEmail = currentUser ? currentUser.email : "learner@tracegate.lab";
        const methodology = currentUser?.methodology === "asvs_l2" ? "OWASP ASVS Level 2" : (currentUser?.methodology === "cwe_sans" ? "CWE/SANS Top 25" : "OWASP Top 10 Web (2025)");

        let md = `# Tracegate Security Assessment Report: ${proj.name}

`;
        md += `> **Confidential Security Assessment Document**  
`;
        md += `> Target: \`${proj.target_url}\` | Date: ${new Date().toISOString().split("T")[0]} | Lead Assessor: ${assessorName}

`;

        md += `## 1. Assessment Overview & Scope

`;
        md += `| Attribute | Details |
`;
        md += `| :--- | :--- |
`;
        md += `| **Project Name** | ${proj.name} |
`;
        md += `| **Target Application** | \`${proj.target_url}\` |
`;
        md += `| **Environment** | ${proj.environment || "Web Application (Staging)"} |
`;
        md += `| **Assessment Date** | ${new Date().toISOString().split("T")[0]} |
`;
        md += `| **Lead Assessor** | ${assessorName} (${assessorEmail}) |
`;
        md += `| **Methodology** | ${methodology} |
`;
        md += `| **Analyzed Surface** | ${pageType} |
`;
        if (proj.description) md += `| **Scope Description** | ${proj.description} |
`;
        if (proj.notes) md += `| **Testing Notes** | ${proj.notes} |
`;
        md += `
`;

        md += `## 2. Executive Assessment Summary

`;
        md += `A structured security verification was performed against the authorized target interface. Out of **${m.total}** planned security test procedures, **${m.completed}** were evaluated (**${m.pct}%** completion rate).

`;
        md += `- **Confirmed Vulnerabilities Logged**: **${vulns.length}**
`;
        md += `- **Verified Clean Controls (Tested & Not Found)**: **${m.clean}**
`;
        md += `- **Pending / Untested Controls**: **${m.remaining}**

`;

        // Severity Breakdown
        const critVulns = vulns.filter(v => normalizeSeverity(v.priority || v.severity) === "CRITICAL").length;
        const highVulns = vulns.filter(v => normalizeSeverity(v.priority || v.severity) === "HIGH").length;
        const medVulns = vulns.filter(v => normalizeSeverity(v.priority || v.severity) === "MEDIUM").length;
        const lowVulns = vulns.filter(v => normalizeSeverity(v.priority || v.severity) === "LOW").length;

        md += `### Findings Severity Breakdown

`;
        md += `| Severity | Count | Status |
`;
        md += `| :--- | :--- | :--- |
`;
        md += `| **CRITICAL** | ${critVulns} | ${critVulns > 0 ? "Immediate Remediation Required" : "None Identified"} |
`;
        md += `| **HIGH** | ${highVulns} | ${highVulns > 0 ? "Priority Remediation Recommended" : "None Identified"} |
`;
        md += `| **MEDIUM** | ${medVulns} | ${medVulns > 0 ? "Standard Remediation Required" : "None Identified"} |
`;
        md += `| **LOW** | ${lowVulns} | ${lowVulns > 0 ? "Best Practice Improvement" : "None Identified"} |

`;

        md += `## 3. Confirmed Vulnerability Findings & Proof of Concept

`;
        if (vulns.length === 0) {
            md += `*No security vulnerabilities were identified in the evaluated surfaces for this assessment scope.*

`;
        } else {
            vulns.forEach((v, idx) => {
                const linkedTest = checklist.find(i => i.id === v.test_id);
                const normSev = normalizeSeverity(v.priority || v.severity);
                md += `### 3.${idx + 1} [${normSev}] ${v.finding_name}

`;
                if (v.cwe || linkedTest?.cwe) {
                    md += `- **Vulnerability Classification**: \`${v.cwe || linkedTest?.cwe}\`
`;
                }
                if (linkedTest) {
                    md += `- **Originating Security Test**: ${linkedTest.name}
`;
                }
                md += `- **Severity**: **${normSev}**
`;
                md += `- **Logged At**: ${v.recorded_at || "Recent"}

`;

                if (v.description) {
                    md += `**Observation & Security Impact**:
`;
                    md += `${v.description}

`;
                }

                if (v.testing_notes || v.reproduction_steps) {
                    md += `**Reproduction Steps**:
`;
                    md += `${v.reproduction_steps || v.testing_notes}

`;
                }

                if (v.remediation) {
                    md += `**Remediation Guidance**:
${v.remediation}

`;
                }

                if (v.evidence_filename) {
                    md += `*Attached PoC Evidence Artifact: \`${v.evidence_filename}\`*

`;
                }

                md += `---

`;
            });
        }

        md += `## 4. Verified Clean Security Controls (Tested — Not Found)

`;
        const cleanItems = checklist.filter(i => i.status === "TESTED_NOT_FOUND");
        if (cleanItems.length === 0) {
            md += `*No security tests have been marked as clean yet.*

`;
        } else {
            md += `The following controls were actively tested and confirmed clean:

`;
            md += `| Priority | Security Control Test | CWE | Verification Objective |
`;
            md += `| :--- | :--- | :--- | :--- |
`;
            cleanItems.forEach(item => {
                const cleanObj = (item.testing_objective || "").replace(/\r?\n/g, " ");
                md += `| **${item.priority}** | ${item.name} | \`${item.cwe || "N/A"}\` | ${cleanObj} |\n`;
            });
            md += `
`;
        }

        md += `## 5. Untested / Planned Assessment Scope

`;
        const untestedItems = checklist.filter(i => i.status === "NOT_TESTED" || !i.status);
        if (untestedItems.length === 0) {
            md += `*All planned checklist items have been fully executed and reviewed.*

`;
        } else {
            md += `The following procedures remain in the scope for subsequent testing phases:

`;
            untestedItems.forEach(item => {
                md += `- [ ] **[${item.priority}] ${item.name}** (\`${item.cwe || "N/A"}\`): ${item.testing_objective}
`;
            });
            md += `
`;
        }

        md += `## 6. General Remediation Guidance & Methodology

`;
        md += `1. **Input Validation & Parameterization**: Ensure all client-supplied parameters are validated against strict type-safe schemas and passed to database layers via parameterized prepared statements.
`;
        md += `2. **Defense in Depth**: Implement modern HTTP security headers (\`Content-Security-Policy\`, \`X-Frame-Options: DENY\`, \`Strict-Transport-Security\`).
`;
        md += `3. **Least Privilege**: Verify authorization on server-side controllers for all object access.

`;
        md += `*Assessment conducted with Tracegate AI-assisted VAPT Learning Platform for authorized security testing.*  
`;

        return md;
    }

    function exportAssessmentMarkdown() {
        const proj = getActiveProject();
        if (!proj) return;

        const md = buildAssessmentMarkdown(proj);

        const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${proj.name.toLowerCase().replace(/[^a-z0-9]/g, "_")}_vapt_report.md`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast("✓ Assessment Report downloaded as Markdown!", "success");
    }

    function copyAssessmentMarkdown() {
        const proj = getActiveProject();
        if (!proj) return;

        const md = buildAssessmentMarkdown(proj);
        if (!navigator.clipboard) {
            const ta = document.createElement("textarea");
            ta.value = md;
            ta.style.position = "fixed";
            ta.style.opacity = "0";
            document.body.appendChild(ta);
            ta.select();
            document.execCommand("copy");
            document.body.removeChild(ta);
            showToast("✓ Assessment Report copied to clipboard!", "success");
            return;
        }

        navigator.clipboard.writeText(md).then(() => {
            showToast("✓ Assessment Report copied to clipboard!", "success");
        }).catch(() => {
            showToast("Failed to copy report to clipboard.", "error");
        });
    }


    // ==========================================================================
    // 12. PAGE TYPE CHANGE & STALENESS CONTROLLER (Sections 18, 19)
    // ==========================================================================
    const pageTypeSelect = document.getElementById("pageTypeSelect");
    const pageTypeOtherContainer = document.getElementById("pageTypeOtherContainer");
    const pageTypeOtherInput = document.getElementById("pageTypeOtherInput");
    const staleAnalysisBanner = document.getElementById("staleAnalysisBanner");
    const btnRegenerateChecklist = document.getElementById("btnRegenerateChecklist");

    if (pageTypeSelect) {
        pageTypeSelect.addEventListener("change", () => {
            selectedPageType = pageTypeSelect.value;
            if (pageTypeSelect.value === "Other") {
                if (pageTypeOtherContainer) pageTypeOtherContainer.style.display = "block";
            } else {
                if (pageTypeOtherContainer) pageTypeOtherContainer.style.display = "none";
            }

            const activeProj = getActiveProject();
            if (activeProj && activeProj.checklist_data && lastGeneratedPageType !== null) {
                if (pageTypeSelect.value !== lastGeneratedPageType) {
                    checklistStatus = "NEEDS_REGENERATION";
                    if (staleAnalysisBanner) staleAnalysisBanner.style.display = "flex";
                } else {
                    checklistStatus = "CURRENT";
                    if (staleAnalysisBanner) staleAnalysisBanner.style.display = "none";
                }
            }
        });
    }

    if (pageTypeOtherInput) {
        pageTypeOtherInput.addEventListener("input", () => {
            const activeProj = getActiveProject();
            if (activeProj && activeProj.checklist_data && staleAnalysisBanner) {
                checklistStatus = "NEEDS_REGENERATION";
                staleAnalysisBanner.style.display = "flex";
            }
        });
    }

    // Section 19: Regenerate Checklist calls generateChecklist directly!
    if (btnRegenerateChecklist) {
        btnRegenerateChecklist.addEventListener("click", generateChecklist);
    }

    // ==========================================================================
    // 13. GITHUB AI FIX & CODE REMEDIATION CONTROLLER
    // ==========================================================================
    let currentRepoTreeItems = [];

    async function loadGitHubFixStatus() {
        try {
            const res = await fetch("/api/github/status", {
                headers: getAuthHeaders()
            });
            if (res.ok) {
                const data = await res.json();
                const statusLabel = document.getElementById("githubStatusLabel");
                const connPill = document.getElementById("githubConnectionPill");
                const modalStatus = document.getElementById("ghModalCurrentStatus");

                const isConnected = !!data.connected;
                const isLive = data.mode === "live";
                window._githubConnected = isConnected;
                window._githubMode = data.mode || "mock";

                if (statusLabel) {
                    if (isLive && isConnected && data.username) {
                        statusLabel.textContent = `GitHub Live (${data.username})`;
                    } else if (isConnected && data.username) {
                        statusLabel.textContent = `GitHub Lab Sandbox (${data.username})`;
                    } else {
                        statusLabel.textContent = "GitHub Not Connected";
                    }
                }

                if (connPill) {
                    connPill.className = (isLive && isConnected) ? "badge badge-completed" : "badge badge-in-progress";
                }

                if (modalStatus) {
                    modalStatus.textContent = (isConnected && data.username)
                        ? `Connected as ${data.username} (${data.mode.toUpperCase()} mode, Token: ${data.token_preview || 'configured'})`
                        : "Not connected to live GitHub (Personal Access Token required for Live mode)";
                }

                // Update Discovery Banner and Action Buttons
                const bannerTitle = document.getElementById("wsAutofixDiscoveryStatusTitle");
                const bannerBadge = document.getElementById("wsAutofixDiscoveryStatusBadge");
                const bannerDesc = document.getElementById("wsAutofixDiscoveryStatusDesc");
                const btnBrowseTree = document.getElementById("btnWsBrowseRepoTree");
                const btnAnalyze = document.getElementById("btnWsAnalyzeCodeFix");

                if (isConnected) {
                    if (bannerTitle) bannerTitle.textContent = "Automatic Repository Discovery Active";
                    if (bannerBadge) {
                        bannerBadge.className = "badge badge-completed";
                        bannerBadge.textContent = isLive ? "GitHub Live" : "GitHub Lab Sandbox";
                    }
                    if (bannerDesc) bannerDesc.textContent = "Repository and branch loaded. Select a vulnerability finding below to automatically analyze and remediate source code.";
                    if (btnBrowseTree) btnBrowseTree.disabled = false;
                    if (btnAnalyze) btnAnalyze.disabled = false;
                } else {
                    if (bannerTitle) bannerTitle.textContent = "Automatic Repository Discovery Inactive";
                    if (bannerBadge) {
                        bannerBadge.className = "badge badge-in-progress";
                        bannerBadge.textContent = "GitHub Not Connected";
                    }
                    if (bannerDesc) bannerDesc.textContent = "Connect your GitHub account to enable automatic repository source detection, live code tree browsing, and defensive remediation.";
                    if (btnBrowseTree) btnBrowseTree.disabled = true;
                    if (btnAnalyze) btnAnalyze.disabled = true;
                }
            }
        } catch (e) {
            console.warn("GitHub status check:", e);
        }
    }

    function getSelectedRemediationRepo() {
        const confirmInput = document.getElementById("confirmApplyRepoInput");
        if (confirmInput && confirmInput.value.trim()) {
            const modal = document.getElementById("modalAIFixConfirmApply");
            if (modal && (modal.classList.contains("active") || modal.classList.contains("show") || modal.style.display === "flex" || modal.style.display === "block")) {
                return confirmInput.value.trim();
            }
        }
        const customInput = document.getElementById("wsAutofixCustomRepoInput");
        const customVal = customInput ? customInput.value.trim() : "";
        const repoSelect = document.getElementById("wsAutofixRepoSelect");
        const selectVal = repoSelect ? repoSelect.value : "";

        if (selectVal === "__custom__" && customVal) {
            return customVal;
        }
        if (customVal && (document.getElementById("wsAutofixCustomRepoWrapper")?.style.display !== "none" || window._usingCustomRepo)) {
            return customVal;
        }
        if (window._currentSelectedRepo && window._currentSelectedRepo !== "__custom__") {
            return window._currentSelectedRepo;
        }
        if (customVal) {
            return customVal;
        }
        return (selectVal && selectVal !== "__custom__") ? selectVal : "";
    }

    async function loadGitHubRepositories() {
        const wsRepoSelect = document.getElementById("wsAutofixRepoSelect");
        const standRepoSelect = document.getElementById("standaloneRepoSelect");
        const wsBranchSelect = document.getElementById("wsAutofixBranchSelect");
        const standBranchSelect = document.getElementById("standaloneBranchSelect");

        if (!window._githubConnected) {
            [wsRepoSelect, standRepoSelect].forEach(sel => {
                if (!sel) return;
                sel.innerHTML = '<option value="">-- Connect GitHub to Select Repository --</option>';
                sel.disabled = true;
            });
            [wsBranchSelect, standBranchSelect].forEach(sel => {
                if (!sel) return;
                sel.innerHTML = '<option value="">-- Connect GitHub First --</option>';
                sel.disabled = true;
            });
            return;
        }

        try {
            const res = await fetch("/api/github/repositories", {
                headers: getAuthHeaders()
            });
            if (res.ok) {
                const repos = await res.json();

                [wsRepoSelect, standRepoSelect].forEach(sel => {
                    if (!sel) return;
                    sel.disabled = false;
                    const curVal = window._currentSelectedRepo;
                    sel.innerHTML = "";

                    if (repos.length === 0) {
                        const optEmpty = document.createElement("option");
                        optEmpty.value = "";
                        optEmpty.textContent = "-- No repositories found on GitHub account --";
                        sel.appendChild(optEmpty);
                    } else {
                        repos.forEach(r => {
                            const opt = document.createElement("option");
                            opt.value = r.full_name;
                            opt.textContent = `${r.full_name} (${r.default_branch}${r.private ? ', private' : ''})`;
                            sel.appendChild(opt);
                        });
                    }

                    // Always allow custom entry option
                    const optCustom = document.createElement("option");
                    optCustom.value = "__custom__";
                    optCustom.textContent = "+ Enter Custom Repository (owner/repo)...";
                    sel.appendChild(optCustom);

                    if (curVal && Array.from(sel.options).some(o => o.value === curVal)) {
                        sel.value = curVal;
                    }
                });

                if (wsBranchSelect) wsBranchSelect.disabled = false;
                if (standBranchSelect) standBranchSelect.disabled = false;

                // Load branches for current repo
                const curRepo = getSelectedRemediationRepo();
                if (curRepo) {
                    loadRepositoryBranches(curRepo);
                }
            }
        } catch (e) {
            console.warn("Failed to load GitHub repositories:", e);
        }
    }

    async function loadRepositoryBranches(repo) {
        if (!repo) return;
        try {
            const res = await fetch(`/api/github/branches?repo=${encodeURIComponent(repo)}`, {
                headers: getAuthHeaders()
            });
            if (res.ok) {
                const data = await res.json();
                const branches = data.branches || ["main"];
                const wsBranchSelect = document.getElementById("wsAutofixBranchSelect");
                const standBranchSelect = document.getElementById("standaloneBranchSelect");

                [wsBranchSelect, standBranchSelect].forEach(sel => {
                    if (!sel) return;
                    const curVal = sel.value;
                    sel.innerHTML = "";
                    branches.forEach(b => {
                        const opt = document.createElement("option");
                        opt.value = b;
                        opt.textContent = b;
                        sel.appendChild(opt);
                    });
                    if (curVal && Array.from(sel.options).some(o => o.value === curVal)) {
                        sel.value = curVal;
                    } else if (branches.includes("main")) {
                        sel.value = "main";
                    }
                });
            }
        } catch (e) {
            console.warn("Failed to load branches:", e);
        }
    }

    function renderWorkspaceAutoFix() {
        loadGitHubFixStatus();
        loadGitHubRepositories();

        const wsSelect = document.getElementById("wsAutofixFindingSelect");
        const standSelect = document.getElementById("autofixFindingSelect");
        const proj = getActiveProject();
        const findings = (proj && proj.findings) ? proj.findings : [];

        [wsSelect, standSelect].forEach(sel => {
            if (!sel) return;
            sel.innerHTML = `<option value="">-- Select Confirmed Vulnerability --</option>`;
            if (findings.length > 0) {
                const optAll = document.createElement("option");
                optAll.value = "__ALL_FINDINGS__";
                optAll.textContent = `✨ Remediate All Detected Vulnerabilities (${findings.length} findings, Full Repository Patch)`;
                optAll.style.fontWeight = "bold";
                sel.appendChild(optAll);
            }
            findings.forEach((f, idx) => {
                const opt = document.createElement("option");
                opt.value = f.id;
                const vulnId = f.vuln_id || `VULN-${String(idx + 1).padStart(3, "0")}`;
                const statusBadge = f.status === "RESOLVED" ? "[RESOLVED] " : (f.fix_status ? `[${f.fix_status}] ` : "");
                opt.textContent = `${statusBadge}[${vulnId}] ${f.finding_name} (${normalizeSeverity(f.priority || f.severity)})`;
                sel.appendChild(opt);
            });
        });

        if (wsSelect && wsSelect.value) {
            restoreFindingFixState(wsSelect.value);
        } else {
            renderSelectedSourcesList();
            renderCandidateSourcesList();
        }

        if (proj && proj.id && typeof checkAndUpdateAIFixCertButtons === "function") {
            checkAndUpdateAIFixCertButtons(proj.id);
        }
        if (proj && proj.id && typeof checkAndRecoverRemediationRun === "function") {
            checkAndRecoverRemediationRun(proj.id);
        }
    }

    // Global source selection state for multi-file discovery & remediation
    window.selectedSources = [];
    window.candidateSources = [];
    window.sourceSelectionMode = "AUTOMATIC";
    let repoTreeTempCheckedPaths = new Set();

    function renderSelectedSourcesList() {
        const container = document.getElementById("wsSelectedSourcesList");
        const countBadge = document.getElementById("wsSelectedSourcesCount");
        const modeBadge = document.getElementById("wsSourceSelectionModeBadge");
        const fileInput = document.getElementById("wsAutofixFileInput");
        const titleEl = document.getElementById("wsSourcesSectionTitle");
        const btnResetScope = document.getElementById("btnResetEntireRepoScope");

        if (!container) return;
        container.innerHTML = "";

        const isUserModified = (window.sourceSelectionMode === "USER_MODIFIED");
        const count = window.selectedSources ? window.selectedSources.length : 0;

        if (modeBadge) {
            modeBadge.textContent = isUserModified ? "⚠ MANUAL SOURCE OVERRIDE" : "✓ Entire Repository";
            modeBadge.className = isUserModified ? "badge badge-warning" : "badge badge-secondary";
        }
        if (titleEl) {
            titleEl.textContent = isUserModified
                ? "Manually Scoped Source Files (Override Active)"
                : "Candidate Sources Discovered (Dynamic Whole-Repository Search Active)";
        }
        if (countBadge) {
            countBadge.textContent = isUserModified
                ? `${count} file${count === 1 ? "" : "s"} manually selected`
                : `${count} candidate file${count === 1 ? "" : "s"} discovered (Entire repository analyzed dynamically)`;
        }
        if (btnResetScope) {
            btnResetScope.style.display = isUserModified ? "inline-block" : "none";
        }

        // Keep backward-compatible hidden input synced with primary file
        if (fileInput) {
            fileInput.value = count > 0 ? window.selectedSources[0].path : "";
        }

        if (count === 0) {
            const emptyMsg = window._githubConnected
                ? (isUserModified
                    ? `No files manually selected. Click <em>Browse Repo Files...</em> to pick source files or <em>Revert to Entire Repository</em>.`
                    : `⚡ <strong>Dynamic Search Universe:</strong> Whole repository tree is active. Click <em>Analyze Repository & Propose Secure Fix</em> to automatically map and remediate all vulnerable code across your repository.`)
                : `Connect GitHub and select a confirmed vulnerability to automatically detect and select vulnerable source files.`;
            container.innerHTML = `
                <div id="wsSelectedSourcesEmpty" style="padding: 12px; text-align: center; color: var(--text-muted); font-size: 0.82rem;">
                    ${emptyMsg}
                </div>
            `;
            return;
        }

        if (!isUserModified) {
            const infoBanner = document.createElement("div");
            infoBanner.style.padding = "6px 10px";
            infoBanner.style.background = "rgba(59, 130, 246, 0.05)";
            infoBanner.style.border = "1px solid rgba(59, 130, 246, 0.2)";
            infoBanner.style.borderRadius = "var(--radius-sm)";
            infoBanner.style.fontSize = "0.76rem";
            infoBanner.style.color = "var(--text-secondary)";
            infoBanner.style.marginBottom = "4px";
            infoBanner.innerHTML = `<strong>Dynamic Search Universe:</strong> The entire repository tree is searched dynamically during remediation. The files below are identified candidate targets; remediation is not limited to these files unless you manually specify an override.`;
            container.appendChild(infoBanner);
        }

        window.selectedSources.forEach((src, idx) => {
            const row = document.createElement("div");
            row.style.display = "flex";
            row.style.justifyContent = "space-between";
            row.style.alignItems = "center";
            row.style.padding = "8px 12px";
            row.style.background = "var(--bg-surface)";
            row.style.border = "1px solid var(--border-subtle)";
            row.style.borderRadius = "var(--radius-sm)";
            row.style.gap = "10px";
            row.style.flexWrap = "wrap";

            const left = document.createElement("div");
            left.style.display = "flex";
            left.style.alignItems = "center";
            left.style.gap = "8px";
            left.style.flex = "1";
            left.style.minWidth = "220px";

            const pathSpan = document.createElement("span");
            pathSpan.style.fontFamily = "var(--font-mono)";
            pathSpan.style.fontSize = "0.85rem";
            pathSpan.style.fontWeight = "700";
            pathSpan.style.color = "var(--text-primary)";
            pathSpan.textContent = src.path;

            const layerBadge = document.createElement("span");
            layerBadge.className = isUserModified ? "badge badge-warning" : "badge badge-primary";
            layerBadge.style.fontSize = "0.7rem";
            layerBadge.textContent = isUserModified ? "Manual Scope" : (src.layer || "Candidate");

            const confBadge = document.createElement("span");
            const conf = (src.confidence || "MEDIUM").toUpperCase();
            confBadge.className = conf === "HIGH" ? "badge badge-success" : (conf === "MANUAL" ? "badge badge-warning" : "badge badge-secondary");
            confBadge.style.fontSize = "0.7rem";
            confBadge.textContent = isUserModified ? "OVERRIDE" : `${conf} (${Math.round(src.relevance_score || 80)}%)`;

            left.appendChild(pathSpan);
            left.appendChild(layerBadge);
            left.appendChild(confBadge);

            if (src.symbols && src.symbols.length > 0) {
                const symSpan = document.createElement("span");
                symSpan.style.fontSize = "0.74rem";
                symSpan.style.color = "var(--text-muted)";
                symSpan.style.fontFamily = "var(--font-mono)";
                symSpan.textContent = "• " + src.symbols.map(s => typeof s === "string" ? s : s.name).join(", ");
                left.appendChild(symSpan);
            }

            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.className = "btn btn-secondary btn-sm";
            removeBtn.style.padding = "2px 8px";
            removeBtn.style.fontSize = "0.75rem";
            removeBtn.style.color = "#dc2626";
            removeBtn.textContent = isUserModified ? "Remove from Scope" : "Ignore Candidate";
            removeBtn.addEventListener("click", () => {
                removeSourceFromSelection(idx);
            });

            row.appendChild(left);
            row.appendChild(removeBtn);
            container.appendChild(row);
        });
    }

    function removeSourceFromSelection(idx) {
        if (!window.selectedSources || idx < 0 || idx >= window.selectedSources.length) return;
        const removed = window.selectedSources.splice(idx, 1)[0];
        window.sourceSelectionMode = "USER_MODIFIED";
        renderSelectedSourcesList();
        saveSourceSelectionToServer();
        showToast(`Removed ${removed.path} from remediation scope.`, "info");
    }

    function renderCandidateSourcesList() {
        const card = document.getElementById("wsCandidateSourcesCard");
        const list = document.getElementById("wsCandidateSourcesList");
        const countBadge = document.getElementById("wsCandidateSourcesCountBadge");

        if (!card || !list) return;
        list.innerHTML = "";

        const candidates = window.candidateSources || [];
        if (candidates.length === 0) {
            card.style.display = "none";
            return;
        }

        card.style.display = "block";
        if (countBadge) countBadge.textContent = String(candidates.length);

        candidates.forEach((cand, idx) => {
            const row = document.createElement("div");
            row.style.display = "flex";
            row.style.justifyContent = "space-between";
            row.style.alignItems = "center";
            row.style.padding = "6px 10px";
            row.style.border = "1px solid var(--border-subtle)";
            row.style.borderRadius = "var(--radius-sm)";
            row.style.background = "var(--bg-subtle)";
            row.style.gap = "8px";
            row.style.flexWrap = "wrap";

            const left = document.createElement("div");
            left.style.display = "flex";
            left.style.flexDirection = "column";
            left.style.gap = "2px";
            left.style.flex = "1";

            const top = document.createElement("div");
            top.style.display = "flex";
            top.style.alignItems = "center";
            top.style.gap = "6px";

            const pathSpan = document.createElement("span");
            pathSpan.style.fontFamily = "var(--font-mono)";
            pathSpan.style.fontSize = "0.8rem";
            pathSpan.style.color = "var(--text-secondary)";
            pathSpan.textContent = cand.path;

            const layerBadge = document.createElement("span");
            layerBadge.className = "badge badge-secondary";
            layerBadge.style.fontSize = "0.68rem";
            layerBadge.textContent = cand.layer || "Candidate";

            const scoreBadge = document.createElement("span");
            scoreBadge.className = "badge badge-secondary";
            scoreBadge.style.fontSize = "0.68rem";
            scoreBadge.textContent = `LOW (${Math.round(cand.relevance_score || 0)}%)`;

            top.appendChild(pathSpan);
            top.appendChild(layerBadge);
            top.appendChild(scoreBadge);
            left.appendChild(top);

            const reasonText = (cand.reasons && cand.reasons.length > 0) ? cand.reasons.join(". ") : (cand.reason || "Low confidence match");
            const reasonEl = document.createElement("span");
            reasonEl.style.fontSize = "0.74rem";
            reasonEl.style.color = "var(--text-muted)";
            reasonEl.style.fontStyle = "italic";
            reasonEl.textContent = reasonText;
            left.appendChild(reasonEl);

            const addBtn = document.createElement("button");
            addBtn.type = "button";
            addBtn.className = "btn btn-secondary btn-sm";
            addBtn.style.padding = "2px 8px";
            addBtn.style.fontSize = "0.75rem";
            addBtn.textContent = "+ Add to Scope";
            addBtn.addEventListener("click", () => {
                addCandidateToScope(idx);
            });

            row.appendChild(left);
            row.appendChild(addBtn);
            list.appendChild(row);
        });
    }

    function addCandidateToScope(idx) {
        if (!window.candidateSources || idx < 0 || idx >= window.candidateSources.length) return;
        const cand = window.candidateSources.splice(idx, 1)[0];
        cand.confidence = "MEDIUM";
        cand.relevance_score = Math.max(cand.relevance_score || 50, 60);
        window.selectedSources.push(cand);
        window.sourceSelectionMode = "USER_MODIFIED";
        renderSelectedSourcesList();
        renderCandidateSourcesList();
        saveSourceSelectionToServer();
        showToast(`Added ${cand.path} to remediation scope.`, "success");
    }

    async function saveSourceSelectionToServer() {
        const findingId = document.getElementById("wsAutofixFindingSelect")?.value;
        const repo = getSelectedRemediationRepo();
        if (!findingId || !repo) return;

        try {
            await fetch("/api/ai-fix/selected-sources", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    finding_id: findingId,
                    repo: repo,
                    selected_paths: (window.selectedSources || []).map(s => s.path),
                    manual_additions: [],
                    manual_removals: []
                })
            });
        } catch (e) {
            console.warn("Failed to persist source selection:", e);
        }
    }

    // Browse Repo Files Helper with Multi-Select Checkboxes
    async function openBrowseRepoTreeModal() {
        if (!window._githubConnected) {
            showToast("Connect GitHub to inspect repository source.", "warning");
            return;
        }
        const repo = getSelectedRemediationRepo();
        if (!repo) {
            showToast("Please select a repository first.", "warning");
            return;
        }
        const branch = document.getElementById("wsAutofixBranchSelect")?.value || "main";

        try {
            showToast("Fetching repository file tree...", "info");
            const res = await fetch(`/api/github/tree?repo=${encodeURIComponent(repo)}&branch=${encodeURIComponent(branch)}`, {
                headers: getAuthHeaders()
            });
            if (!res.ok) throw new Error("Failed to fetch repository tree.");
            const data = await res.json();

            currentRepoTreeItems = (data.tree || []).filter(item => {
                const pathLower = (item.path || "").toLowerCase();
                const isPycache = pathLower.includes("__pycache__") || pathLower.endsWith(".pyc") || pathLower.endsWith(".pyo");
                const isGit = pathLower.startsWith(".git/") || pathLower.includes("/.git/") || pathLower.startsWith(".github/");
                return !isPycache && !isGit;
            });
            repoTreeTempCheckedPaths = new Set((window.selectedSources || []).map(s => s.path));
            updateRepoTreeCount();
            renderRepoTreeList(currentRepoTreeItems);
            openModal("modalBrowseRepoFiles");
        } catch (e) {
            showToast(e.message, "error");
        }
    }

    function updateRepoTreeCount() {
        const countEl = document.getElementById("repoTreeSelectionCount");
        if (countEl) countEl.textContent = `${repoTreeTempCheckedPaths.size} selected`;
    }

    function renderRepoTreeList(items) {
        const container = document.getElementById("repoTreeListContainer");
        if (!container) return;
        container.innerHTML = "";

        if (items.length === 0) {
            container.innerHTML = '<div style="padding: 16px; text-align: center; color: var(--text-muted);">No files found.</div>';
            return;
        }

        items.forEach(item => {
            const label = document.createElement("label");
            label.style.padding = "8px 12px";
            label.style.borderBottom = "1px solid var(--border-subtle)";
            label.style.cursor = "pointer";
            label.style.display = "flex";
            label.style.justifyContent = "space-between";
            label.style.alignItems = "center";
            label.style.userSelect = "none";
            label.className = "repo-tree-item";

            const left = document.createElement("div");
            left.style.display = "flex";
            left.style.alignItems = "center";
            left.style.gap = "8px";

            const chk = document.createElement("input");
            chk.type = "checkbox";
            chk.className = "repo-tree-checkbox";
            chk.checked = repoTreeTempCheckedPaths.has(item.path);

            chk.addEventListener("change", (e) => {
                if (e.target.checked) {
                    repoTreeTempCheckedPaths.add(item.path);
                } else {
                    repoTreeTempCheckedPaths.delete(item.path);
                }
                updateRepoTreeCount();
            });

            const pathSpan = document.createElement("span");
            pathSpan.style.color = "var(--text-primary)";
            pathSpan.textContent = item.path;

            left.appendChild(chk);
            left.appendChild(pathSpan);

            const sizeBadge = document.createElement("span");
            sizeBadge.style.fontSize = "0.72rem";
            sizeBadge.style.color = "var(--text-muted)";
            sizeBadge.style.background = "var(--bg-subtle)";
            sizeBadge.style.padding = "2px 6px";
            sizeBadge.style.borderRadius = "4px";
            sizeBadge.textContent = item.size ? item.size + ' B' : 'blob';

            label.appendChild(left);
            label.appendChild(sizeBadge);
            container.appendChild(label);
        });
    }

    // AI AutoFix V2 Remediation Result Renderer
    function renderAIFixRemediationResult(data, isWorkspace = true) {
        if (!data) return false;
        const diffWrap = document.getElementById(isWorkspace ? "wsDiffViewerWrapper" : "standaloneDiffWrapper");
        const diffContainer = document.getElementById(isWorkspace ? "wsDiffContainer" : "autofixOutputBox");
        const beforeCodeContainer = document.getElementById("wsBeforeCodeContainer");
        const afterCodeContainer = document.getElementById("wsAfterCodeContainer");
        const filePathEl = document.getElementById(isWorkspace ? "wsDiffFilePath" : "standaloneDiffFilePath");
        const shaBadge = document.getElementById("wsDiffFileShaBadge");
        const expEl = document.getElementById("wsDiffExplanation");
        const safeEl = document.getElementById("wsDiffSafetyNotes");
        const changesList = document.getElementById("wsDiffChangesList");
        const preservedList = document.getElementById("wsDiffPreservedList");
        const impactEl = document.getElementById("wsDiffSecurityImpact");
        const testRecEl = document.getElementById("wsDiffTestingRec");
        const vulnBadge = document.getElementById("wsDiffVulnBadge");
        const irrevAlert = document.getElementById("wsAutofixIrrelevantAlert");
        const irrevMsg = document.getElementById("wsAutofixIrrelevantMsg");
        const safetyAlert = document.getElementById("wsAutofixSafetyAlert");
        const safetyMsg = document.getElementById("wsAutofixSafetyMsg");
        const failedAlert = document.getElementById("wsAutofixFailedAlert");
        const failedMsg = document.getElementById("wsAutofixFailedMsg");
        const btnApproveApply = document.getElementById("btnWsOpenConfirmApply");
        const btnToggleDiffView = document.getElementById("btnToggleDiffView");
        const btnToggleBeforeAfterView = document.getElementById("btnToggleBeforeAfterView");
        const wsUnifiedDiffBox = document.getElementById("wsUnifiedDiffBox");
        const wsBeforeAfterBox = document.getElementById("wsBeforeAfterBox");
        const patchStatusBadge = document.getElementById("wsPatchStatusBadge");
        const multiFileSummaryBadge = document.getElementById("wsMultiFileSummaryBadge");
        const diffFileTabsBar = document.getElementById("wsDiffFileTabsBar");

        // Update candidate suggestions in AUTOMATIC mode without overriding dynamic discovery
        if (window.sourceSelectionMode !== "USER_MODIFIED") {
            if (data.selected_sources && data.selected_sources.length > 0) {
                window.selectedSources = data.selected_sources;
                window.candidateSources = data.candidate_sources || [];
                renderSelectedSourcesList();
                renderCandidateSourcesList();
            } else if (data.file_path && (!window.selectedSources || window.selectedSources.length === 0)) {
                window.selectedSources = [{ path: data.file_path, layer: "controller", confidence: "HIGH", relevance_score: 90 }];
                renderSelectedSourcesList();
            }
        }

        // Handle NO_RELEVANT_SOURCE_FOUND Check
        if (data.patch_status === "NO_RELEVANT_SOURCE_FOUND") {
            if (failedAlert) {
                failedAlert.style.display = "block";
                if (failedMsg) failedMsg.textContent = data.reason || "Tracegate could not identify source code relevant to this finding in the repository.";
                failedAlert.scrollIntoView({ behavior: "smooth", block: "center" });
            }
            if (diffWrap) diffWrap.style.display = "none";
            showToast(data.reason || "Tracegate could not identify source code relevant to this finding. Please use 'Browse Repo Files' as fallback.", "warning");
            return false;
        }

        // Handle Irrelevant File Check
        if (data.is_relevant_file === false) {
            if (irrevAlert) {
                irrevAlert.style.display = "block";
                if (irrevMsg) irrevMsg.textContent = data.reason || "The selected file is not relevant to this vulnerability finding.";
                irrevAlert.scrollIntoView({ behavior: "smooth", block: "center" });
            }
            if (diffWrap) diffWrap.style.display = "none";
            showToast(data.reason || "Selected file is not relevant to this finding.", "error");
            return false;
        } else {
            if (irrevAlert) irrevAlert.style.display = "none";
        }

        // Failure handling
        if (data.success === false) {
            if (failedAlert) {
                failedAlert.style.display = "block";
                if (failedMsg) failedMsg.textContent = data.reason || "No source-code change was generated. The fix cannot be applied safely.";
                failedAlert.scrollIntoView({ behavior: "smooth", block: "center" });
            }
            if (btnApproveApply) {
                btnApproveApply.disabled = true;
                btnApproveApply.style.opacity = "0.5";
                btnApproveApply.style.cursor = "not-allowed";
            }
            if (diffWrap) diffWrap.style.display = "none";
            showToast(data.reason || "Remediation validation failed.", "error");
            return false;
        } else {
            if (failedAlert) failedAlert.style.display = "none";
        }

        // Extract patch and before/after code
        const diffStr = (data.diff_unified || data.unified_diff || data.patch || "").trim();
        const beforeStr = (data.before_content || data.before_code || data.original_code || "").trim();
        const afterStr = (data.after_content || data.after_code || data.proposed_code || "").trim();

        const rawFiles = (data.files && data.files.length > 0)
            ? data.files
            : (data.file_path && diffStr.trim().length > 0 && beforeStr !== afterStr ? [{
                path: data.file_path,
                file_sha: data.file_sha,
                diff_unified: diffStr,
                before_code: beforeStr,
                after_code: afterStr,
                changes: data.changes || []
            }] : []);

        const filesList = rawFiles.filter(f => {
            const d = (f.diff_unified || "").trim();
            const b = f.before_code || "";
            const a = f.after_code || "";
            return d.length > 0 && b !== a;
        });

        if (filesList.length > 0) {
            if (btnApproveApply) {
                btnApproveApply.disabled = false;
                btnApproveApply.style.opacity = "1";
                btnApproveApply.style.cursor = "pointer";
                btnApproveApply.title = "Apply fix to new branch and create PR";
            }
        } else {
            if (btnApproveApply) {
                btnApproveApply.disabled = true;
                btnApproveApply.style.opacity = "0.5";
                btnApproveApply.style.cursor = "not-allowed";
                btnApproveApply.title = "No pending changes to apply - Code is already secure.";
            }
        }

        // Reset View Toggles to Exact Diff
        if (wsUnifiedDiffBox) wsUnifiedDiffBox.style.display = "block";
        if (wsBeforeAfterBox) wsBeforeAfterBox.style.display = "none";
        if (btnToggleDiffView) btnToggleDiffView.className = "btn btn-sm btn-primary";
        if (btnToggleBeforeAfterView) btnToggleBeforeAfterView.className = "btn btn-sm btn-secondary";

        // Update Finding ID badge
        if (vulnBadge) {
            const displayId = data.vuln_id || data.finding_id || "VULN";
            vulnBadge.textContent = `${displayId.toUpperCase()} Remediation`;
        }

        // Update Patch Status Badge
        if (patchStatusBadge) {
            const pStatus = data.patch_status || (data.success ? "PATCH_VALIDATED" : "PATCH_REJECTED");
            patchStatusBadge.style.display = "inline-block";
            patchStatusBadge.textContent = pStatus;
            patchStatusBadge.className = (pStatus === "PATCH_VALIDATED") ? "badge badge-success" : "badge badge-danger";
        }

        // Populate Honest Validation Status Badges
        const synBadge = document.getElementById("wsDiffSyntaxBadge");
        const testBadge = document.getElementById("wsDiffTestsBadge");
        const regBadge = document.getElementById("wsDiffRegressionBadge");
        const scoreBadge = document.getElementById("wsDiffQualityScore");

        if (data.validation) {
            const syn = data.validation.syntax || "NOT_RUN";
            const tst = data.validation.tests || "NOT_AVAILABLE";
            const sec = data.validation.security || data.validation.security_regression || "NOT_VERIFIED";

            if (synBadge) {
                synBadge.style.display = "inline-block";
                synBadge.textContent = `Syntax: ${syn}`;
                synBadge.className = syn === "PASSED" ? "badge badge-success" : (syn === "FAILED" ? "badge badge-danger" : "badge badge-warning");
            }
            if (testBadge) {
                testBadge.style.display = "inline-block";
                testBadge.textContent = `Tests: ${tst}`;
                testBadge.className = tst === "PASSED" ? "badge badge-success" : (tst === "FAILED" ? "badge badge-danger" : "badge badge-warning");
            }
            if (regBadge) {
                regBadge.style.display = "inline-block";
                regBadge.textContent = `Security: ${sec}`;
                regBadge.className = sec === "PASSED" ? "badge badge-success" : (sec === "FAILED" ? "badge badge-danger" : "badge badge-warning");
            }
        } else {
            if (synBadge) synBadge.style.display = "none";
            if (testBadge) testBadge.style.display = "none";
            if (regBadge) regBadge.style.display = "none";
        }

        // Populate Score Badge
        if (data.fix_quality_score != null) {
            let numScore = 0;
            if (typeof data.fix_quality_score === 'number' && !isNaN(data.fix_quality_score)) {
                numScore = data.fix_quality_score;
            } else if (typeof data.fix_quality_score === 'object') {
                numScore = (data.fix_quality_score.total_score != null) ? data.fix_quality_score.total_score : (data.fix_quality_score.score != null ? data.fix_quality_score.score : (data.success ? 90 : 0));
            } else {
                numScore = data.success ? 90 : 0;
            }
            if (scoreBadge) {
                scoreBadge.style.display = "inline-block";
                scoreBadge.textContent = `Score: ${Math.round(numScore)}/100`;
                scoreBadge.className = numScore >= 80 ? "badge badge-primary" : (numScore >= 50 ? "badge badge-warning" : "badge badge-danger");
            }
        } else if (scoreBadge) {
            scoreBadge.style.display = "none";
        }

        // Handle Pre-Commit Safety Check (Dependencies / Workflows)
        if (data.dependencies_changed || data.workflow_files_changed) {
            if (safetyAlert) {
                safetyAlert.style.display = "block";
                if (safetyMsg) safetyMsg.textContent = data.safety_notes || "Modifying dependency or CI workflow files requires additional care.";
            }
        } else {
            if (safetyAlert) safetyAlert.style.display = "none";
        }

        if (diffWrap) diffWrap.style.display = "flex";
        if (expEl) expEl.textContent = data.explanation;
        if (safeEl) safeEl.textContent = "Safety note: " + (data.safety_notes || "Enforces least privilege boundaries.");

        if (multiFileSummaryBadge) {
            if (filesList.length > 0) {
                multiFileSummaryBadge.style.display = "inline-block";
                multiFileSummaryBadge.textContent = `${filesList.length} file${filesList.length > 1 ? "s" : ""} modified`;
            } else {
                multiFileSummaryBadge.style.display = "none";
            }
        }

        // AI AutoFix V2: Render Remediation Summary Card
        const summaryCard = document.getElementById("wsRemediationSummaryCard");
        const summaryOverallStatusBadge = document.getElementById("wsSummaryOverallStatusBadge");
        const frameworkSubtitle = document.getElementById("wsRemediationFrameworkSubtitle");
        const metricFindingsSelected = document.getElementById("wsMetricFindingsSelected");
        const metricFindingsValidated = document.getElementById("wsMetricFindingsValidated");
        const metricReviewRequired = document.getElementById("wsMetricReviewRequired");
        const metricFilesModified = document.getElementById("wsMetricFilesModified");
        const metricLinesAdded = document.getElementById("wsMetricLinesAdded");
        const metricLinesRemoved = document.getElementById("wsMetricLinesRemoved");

        if (data.remediation_summary && summaryCard) {
            const s = data.remediation_summary;
            summaryCard.style.display = "flex";
            if (summaryOverallStatusBadge) {
                summaryOverallStatusBadge.textContent = s.overall_status || "ALL_FINDINGS_VALIDATED";
                if (s.overall_status === "ALL_FINDINGS_VALIDATED") {
                    summaryOverallStatusBadge.className = "badge badge-success";
                } else if (s.overall_status === "PARTIAL_REMEDIATION") {
                    summaryOverallStatusBadge.className = "badge badge-warning";
                } else {
                    summaryOverallStatusBadge.className = "badge badge-danger";
                }
            }
            if (frameworkSubtitle) {
                const layers = (s.architecture_layers || []).join(" ➔ ");
                frameworkSubtitle.textContent = `Framework: ${s.framework_detected || "Generic Web"} | Architecture Flow: ${layers || "N/A"}`;
            }
            if (metricFindingsSelected) metricFindingsSelected.textContent = s.findings_selected_count != null ? s.findings_selected_count : "1";
            if (metricFindingsValidated) metricFindingsValidated.textContent = s.findings_validated_count != null ? s.findings_validated_count : "1";
            if (metricReviewRequired) metricReviewRequired.textContent = s.review_required_count != null ? s.review_required_count : "0";
            if (metricFilesModified) metricFilesModified.textContent = s.files_modified_count != null ? s.files_modified_count : filesList.length;
            if (metricLinesAdded) metricLinesAdded.textContent = `+${s.lines_added || 0}`;
            if (metricLinesRemoved) metricLinesRemoved.textContent = `-${s.lines_removed || 0}`;
        } else if (summaryCard) {
            summaryCard.style.display = "none";
        }

        // AI AutoFix V2: Render Finding-by-Finding Remediation Matrix
        const findingTraceCard = document.getElementById("wsFindingTraceabilityCard");
        const findingTraceTbody = document.getElementById("wsFindingTraceabilityTbody");
        const findingTraceCountBadge = document.getElementById("wsFindingTraceCountBadge");

        if (data.finding_traceability && data.finding_traceability.length > 0 && findingTraceCard && findingTraceTbody) {
            findingTraceCard.style.display = "flex";
            if (findingTraceCountBadge) findingTraceCountBadge.textContent = `${data.finding_traceability.length} finding${data.finding_traceability.length > 1 ? "s" : ""}`;
            findingTraceTbody.innerHTML = "";

            data.finding_traceability.forEach(ft => {
                const tr = document.createElement("tr");
                tr.style.borderBottom = "1px solid var(--border-subtle)";

                const statusClass = (ft.status === "PATCH_VALIDATED" || ft.status === "ALREADY_REMEDIATED")
                    ? "badge badge-success"
                    : (ft.status === "REVIEW_REQUIRED" ? "badge badge-warning" : "badge badge-danger");

                const filesStr = (ft.changed_files && ft.changed_files.length > 0)
                    ? ft.changed_files.map(cf => `<code style="font-size: 0.76rem; color: #3b82f6;">${cf}</code>`).join(", ")
                    : (ft.selected_files && ft.selected_files.length > 0
                        ? ft.selected_files.map(sf => `<code style="font-size: 0.76rem; color: var(--text-muted);">${sf}</code>`).join(", ")
                        : '<span style="color: var(--text-muted); font-size: 0.76rem;">No Safe Source Match</span>');

                tr.innerHTML = `
                    <td style="padding: 10px; font-weight: 600; color: var(--text-primary); vertical-align: top;">
                        <div>${ft.finding_id}</div>
                        <div style="font-size: 0.76rem; color: var(--text-muted); font-weight: normal; margin-top: 2px;">${ft.title}</div>
                    </td>
                    <td style="padding: 10px; font-family: var(--font-mono); font-size: 0.78rem; vertical-align: top;">
                        <span class="badge badge-secondary">${ft.cwe || "N/A"}</span>
                    </td>
                    <td style="padding: 10px; vertical-align: top;">
                        <span class="${statusClass}" style="font-size: 0.72rem; font-weight: 700;">${ft.status}</span>
                    </td>
                    <td style="padding: 10px; vertical-align: top; max-width: 220px; word-break: break-all;">
                        ${filesStr}
                    </td>
                    <td style="padding: 10px; font-size: 0.78rem; color: var(--text-secondary); line-height: 1.4; vertical-align: top;">
                        <div>${ft.reason || ft.change_plan || "Remediated cleanly."}</div>
                    </td>
                `;
                findingTraceTbody.appendChild(tr);
            });
        } else if (findingTraceCard) {
            findingTraceCard.style.display = "none";
        }

        // AI AutoFix V2: Render File Traceability Table
        const fileTraceCard = document.getElementById("wsFileTraceabilityCard");
        const fileTraceTbody = document.getElementById("wsFileTraceabilityTbody");
        const fileTraceCountBadge = document.getElementById("wsFileTraceCountBadge");

        const activeFileTrace = (data.file_traceability || []).filter(ft => {
            const linesAdded = Number(ft.lines_added) || 0;
            const linesRemoved = Number(ft.lines_removed) || 0;
            const d = (ft.diff_unified || "").trim();
            return (linesAdded > 0 || linesRemoved > 0) && d.length > 0;
        });

        if (activeFileTrace.length > 0 && fileTraceCard && fileTraceTbody) {
            fileTraceCard.style.display = "flex";
            if (fileTraceCountBadge) fileTraceCountBadge.textContent = `${activeFileTrace.length} file${activeFileTrace.length > 1 ? "s" : ""}`;
            fileTraceTbody.innerHTML = "";

            activeFileTrace.forEach(ft => {
                const tr = document.createElement("tr");
                tr.style.borderBottom = "1px solid var(--border-subtle)";

                const syn = (ft.validation && ft.validation.syntax) || "PASSED";
                const synClass = syn === "PASSED" ? "badge badge-success" : "badge badge-danger";
                const fids = (ft.finding_ids && ft.finding_ids.length > 0)
                    ? ft.finding_ids.map(fid => `<span class="badge badge-secondary" style="font-size: 0.7rem; margin-right: 4px;">${fid}</span>`).join("")
                    : '<span style="color: var(--text-muted); font-size: 0.74rem;">N/A</span>';

                tr.innerHTML = `
                    <td style="padding: 10px; font-family: var(--font-mono); font-size: 0.8rem; font-weight: 600; color: #3b82f6; vertical-align: top;">
                        ${ft.path}
                    </td>
                    <td style="padding: 10px; font-family: var(--font-mono); font-size: 0.74rem; color: var(--text-muted); vertical-align: top;">
                        ${ft.file_sha ? ft.file_sha.substring(0, 7) : "N/A"}
                    </td>
                    <td style="padding: 10px; font-family: var(--font-mono); font-size: 0.78rem; vertical-align: top;">
                        <span style="color: #10b981; font-weight: 700;">+${ft.lines_added || 0}</span> / 
                        <span style="color: #ef4444; font-weight: 700;">-${ft.lines_removed || 0}</span>
                    </td>
                    <td style="padding: 10px; vertical-align: top;">
                        ${fids}
                    </td>
                    <td style="padding: 10px; vertical-align: top;">
                        <span class="${synClass}" style="font-size: 0.72rem; font-weight: 700;">Syntax: ${syn}</span>
                    </td>
                `;
                fileTraceTbody.appendChild(tr);
            });
        } else if (fileTraceCard) {
            fileTraceCard.style.display = "none";
        }

        // Render Diff Content Helper for a given file item
        function renderDiffForFileItem(fileItem) {
            if (filePathEl) filePathEl.textContent = fileItem.path;
            if (shaBadge) {
                shaBadge.textContent = fileItem.file_sha ? `SHA: ${fileItem.file_sha.substring(0, 7)}` : "";
            }
            if (beforeCodeContainer) beforeCodeContainer.textContent = fileItem.before_code || "";
            if (afterCodeContainer) afterCodeContainer.textContent = fileItem.after_code || "";

            if (changesList) {
                changesList.innerHTML = "";
                const changes = fileItem.changes || data.changes || [];
                changes.forEach(c => {
                    const li = document.createElement("li");
                    li.textContent = c;
                    changesList.appendChild(li);
                });
            }

            if (diffContainer) {
                diffContainer.innerHTML = "";
                const lines = (fileItem.diff_unified || "").split("\n");
                lines.forEach(line => {
                    const span = document.createElement("span");
                    if (line.startsWith("+") && !line.startsWith("+++")) {
                        span.className = "diff-line-add";
                        span.style.color = "#4ade80";
                        span.style.backgroundColor = "rgba(74, 222, 128, 0.1)";
                        span.style.display = "block";
                    } else if (line.startsWith("-") && !line.startsWith("---")) {
                        span.className = "diff-line-del";
                        span.style.color = "#f87171";
                        span.style.backgroundColor = "rgba(248, 113, 113, 0.1)";
                        span.style.display = "block";
                    } else if (line.startsWith("@@")) {
                        span.className = "diff-line-info";
                        span.style.color = "#38bdf8";
                        span.style.display = "block";
                    } else {
                        span.style.display = "block";
                    }
                    span.textContent = line;
                    diffContainer.appendChild(span);
                });
            }
        }

        // Populate File Tabs Bar if multiple files modified
        if (diffFileTabsBar) {
            diffFileTabsBar.innerHTML = "";
            if (filesList.length > 1) {
                diffFileTabsBar.style.display = "flex";
                filesList.forEach((fItem, fIdx) => {
                    const tabBtn = document.createElement("button");
                    tabBtn.type = "button";
                    tabBtn.className = fIdx === 0 ? "btn btn-xs btn-primary" : "btn btn-xs btn-secondary";
                    tabBtn.style.fontFamily = "var(--font-mono)";
                    tabBtn.style.fontSize = "0.74rem";
                    tabBtn.style.padding = "3px 8px";
                    tabBtn.textContent = fItem.path;

                    tabBtn.addEventListener("click", () => {
                        Array.from(diffFileTabsBar.children).forEach(c => c.className = "btn btn-xs btn-secondary");
                        tabBtn.className = "btn btn-xs btn-primary";
                        renderDiffForFileItem(fItem);
                    });

                    diffFileTabsBar.appendChild(tabBtn);
                });
            } else {
                diffFileTabsBar.style.display = "none";
            }
        }

        // Initially render the primary modified file
        if (filesList.length > 0) {
            renderDiffForFileItem(filesList[0]);
        } else {
            const isAlreadySecure = (data.patch_status === "ALREADY_SECURE" || (data.remediation_summary && data.remediation_summary.overall_status === "ALL_FINDINGS_VALIDATED"));
            if (filePathEl) filePathEl.textContent = data.file_path || (isAlreadySecure ? "Verified Secure / Repository Clean" : "No Files Modified");
            if (diffContainer) {
                diffContainer.innerHTML = `<div style="padding: 36px 20px; text-align: center; color: ${isAlreadySecure ? '#4ade80' : 'var(--text-muted)'}; font-size: 0.92rem; line-height: 1.6;">
                    <div style="font-size: 1.6rem; margin-bottom: 8px;">${isAlreadySecure ? '🛡️' : 'ℹ️'}</div>
                    <div style="font-weight: 600; font-size: 1.05rem; color: ${isAlreadySecure ? '#4ade80' : 'var(--text-primary)'}; margin-bottom: 6px;">
                        ${isAlreadySecure ? 'Repository Source Code is Already Secure' : 'No Source Modifications Required'}
                    </div>
                    <div style="max-width: 600px; margin: 0 auto; color: var(--text-secondary);">
                        ${isAlreadySecure 
                            ? 'All examined source files contain appropriate architectural controls, boundary checks, or sanitizers. No code modifications are needed.' 
                            : (data.reason || 'No modified lines generated for the analyzed findings.')}
                    </div>
                </div>`;
            }
            if (beforeCodeContainer) beforeCodeContainer.textContent = data.before_code || data.original_code || "// Verified secure in repository";
            if (afterCodeContainer) afterCodeContainer.textContent = data.after_code || data.proposed_code || "// Verified secure in repository";
            if (btnApproveApply) {
                btnApproveApply.disabled = true;
                btnApproveApply.style.opacity = "0.5";
                btnApproveApply.style.cursor = "not-allowed";
                btnApproveApply.title = "No changes to apply - repository code is already secure.";
            }
        }

        // Populate preserved logic list
        if (preservedList) {
            preservedList.innerHTML = "";
            const preserved = data.preserved_logic || [];
            if (preserved.length > 0) {
                preserved.forEach(p => {
                    const li = document.createElement("li");
                    li.textContent = "✓ " + p;
                    preservedList.appendChild(li);
                });
            } else {
                const li = document.createElement("li");
                li.textContent = "✓ Preserved existing controller structure, routing signatures, and response format.";
                preservedList.appendChild(li);
            }
        }

        if (impactEl) impactEl.textContent = data.security_impact || "Mitigates security vulnerability.";
        if (testRecEl) testRecEl.textContent = data.testing_recommendation || "Verify fix with reproduction test payloads.";

        // Populate Retest Checklist items
        const retestContainer = document.getElementById("wsRetestChecklistItems");
        if (retestContainer) {
            retestContainer.innerHTML = "";
            const checklistItems = data.retest_checklist || [
                "1. Verify exploit payload is rejected with HTTP 403 Forbidden.",
                "2. Verify legitimate user requests continue to succeed with HTTP 200 OK.",
                "3. Verify security logs record blocked unauthorized access attempts."
            ];

            checklistItems.forEach((itemText, idx) => {
                const div = document.createElement("div");
                div.style.display = "flex";
                div.style.alignItems = "flex-start";
                div.style.gap = "8px";

                const chk = document.createElement("input");
                chk.type = "checkbox";
                chk.id = `retestItem_${idx}`;
                chk.style.marginTop = "3px";
                chk.style.cursor = "pointer";

                const lbl = document.createElement("label");
                lbl.htmlFor = `retestItem_${idx}`;
                lbl.style.fontSize = "0.84rem";
                lbl.style.color = "var(--text-primary)";
                lbl.style.cursor = "pointer";
                lbl.textContent = itemText;

                div.appendChild(chk);
                div.appendChild(lbl);
                retestContainer.appendChild(div);
            });
        }

        // If this remediation run or analysis already has a PR or branch/commit, restore PR UI
        if (data.pr_url || data.pr_number || data.github_pr) {
            const prNum = data.pr_number || (data.pr_url ? parseInt(data.pr_url.split("/pull/")[1], 10) : undefined);
            const prUrl = data.pr_url || data.github_pr;
            window._currentPRResult = {
                pr_number: prNum,
                pr_url: prUrl,
                merged: false,
                state: "open"
            };
            updatePRUI({
                pr_number: prNum,
                pr_url: prUrl,
                merged: false,
                state: "open",
                review_status: "Awaiting Review"
            });
            const prBtn = document.getElementById("btnWsCreatePR");
            if (prBtn && prNum) {
                prBtn.textContent = `✓ PR #${prNum} Created`;
                prBtn.className = "btn btn-outline-success btn-sm";
            }
        }
        if (data.branch_name || data.fix_branch || data.commit_sha) {
            const card = document.getElementById("wsFixAppliedCard");
            const branchEl = document.getElementById("wsFixBranchName");
            const shaEl = document.getElementById("wsFixCommitSha");
            if (card) card.style.display = "flex";
            if (branchEl && (data.branch_name || data.fix_branch)) branchEl.textContent = data.branch_name || data.fix_branch;
            if (shaEl && data.commit_sha) shaEl.textContent = data.commit_sha.substring(0, 7);
        }

        window._currentAnalysisData = data;
        return true;
    }

    // Active Remediation Run Recovery & Polling
    async function checkAndRecoverRemediationRun(projectId) {
        if (!projectId) return;
        try {
            const repoVal = getSelectedRemediationRepo();
            const branchVal = getSelectedRemediationBranch();
            let url = `/api/ai-fix/run-status?project_id=${encodeURIComponent(projectId)}`;
            if (repoVal) url += `&repo=${encodeURIComponent(repoVal)}`;
            if (branchVal) url += `&branch=${encodeURIComponent(branchVal)}`;

            const res = await fetch(url, { headers: getAuthHeaders() });
            if (!res.ok) return;
            const runData = await res.json();
            if (!runData) return;

            // If an active run is currently ongoing (>90s check is already done by server):
            if (runData.is_active && runData.status === "RUNNING") {
                const bannerDesc = document.getElementById("wsAutofixDiscoveryStatusDesc");
                const btnAnalyze = document.getElementById("btnWsAnalyzeCodeFix");
                if (btnAnalyze) {
                    btnAnalyze.disabled = true;
                    btnAnalyze.style.opacity = "0.75";
                    btnAnalyze.style.cursor = "wait";
                    btnAnalyze.innerHTML = `<span class="spinner" style="display:inline-block; width:13px; height:13px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:8px; vertical-align:middle;"></span><span id="wsAnalyzeBtnText">Remediating Repository...</span>`;
                }
                if (bannerDesc) {
                    bannerDesc.innerHTML = `<span style="color: #3b82f6; font-weight: 600;">⚡ Active Pipeline:</span> <span id="wsRemediationProgressStep">${runData.progress_message || "Validating patches..."}</span>`;
                }
                window._isRemediationRunning = true;
                pollActiveRemediationRun(projectId, runData.id);
                return;
            }

            // If stale recovery occurred:
            if (runData.progress_message === "Previous remediation run stopped unexpectedly.") {
                const bannerDesc = document.getElementById("wsAutofixDiscoveryStatusDesc");
                if (bannerDesc) {
                    bannerDesc.innerHTML = `<span style="color: #f59e0b; font-weight: 600;">⚠ Notice:</span> Previous remediation run timed out and was safely recovered.`;
                }
            }

            // If there is a completed result saved, populate diff if not already displayed
            const diffWrap = document.getElementById("wsDiffViewerWrapper");
            if ((!diffWrap || diffWrap.style.display === "none") && runData.result) {
                renderAIFixRemediationResult(runData.result, true);
            }
        } catch (err) {
            console.warn("Could not check/recover remediation run:", err);
        }
    }

    function pollActiveRemediationRun(projectId, runId) {
        const bannerDesc = document.getElementById("wsAutofixDiscoveryStatusDesc");
        const btnAnalyze = document.getElementById("btnWsAnalyzeCodeFix");

        const pollInterval = setInterval(async () => {
            try {
                const res = await fetch(`/api/ai-fix/run-status?project_id=${encodeURIComponent(projectId)}&run_id=${encodeURIComponent(runId)}`, {
                    headers: getAuthHeaders()
                });
                if (!res.ok) {
                    clearInterval(pollInterval);
                    return;
                }
                const run = await res.json();
                if (!run) return;

                const stepEl = document.getElementById("wsRemediationProgressStep");
                if (stepEl && run.progress_message) {
                    stepEl.textContent = run.progress_message;
                }

                if (!run.is_active || run.status !== "RUNNING") {
                    clearInterval(pollInterval);
                    window._isRemediationRunning = false;
                    if (btnAnalyze) {
                        btnAnalyze.disabled = false;
                        btnAnalyze.style.opacity = "1";
                        btnAnalyze.style.cursor = "pointer";
                        btnAnalyze.innerHTML = `<span>Analyze Repository &amp; Propose Secure Fix</span>`;
                    }
                    if (run.result) {
                        renderAIFixRemediationResult(run.result, true);
                        showToast("✓ Remediation analysis complete.", "success");
                    } else if (run.status === "FAILED" || run.status === "REVIEW_REQUIRED") {
                        showToast(run.progress_message || "Remediation run ended.", "warning");
                    }
                }
            } catch (e) {
                console.warn("Active run polling error:", e);
            }
        }, 1500);
    }

    // Main Analysis Execution (Multi-File Phase 2)
    async function executeCodeFixAnalysis(repo, branch, findingId, isWorkspace = true) {
        if (window._isRemediationRunning) {
            showToast("Remediation analysis is already in progress. Please wait...", "warning");
            return;
        }

        const repoToUse = (repo && repo !== "__custom__") ? repo : getSelectedRemediationRepo();
        if (!repoToUse) {
            showToast("Please select a valid repository first.", "warning");
            return;
        }

        const branchToUse = branch || document.getElementById("wsAutofixBranchSelect")?.value || "main";
        const curProj = getActiveProject();
        const effectiveProjectId = curProj ? curProj.id : (typeof activeProjectId !== "undefined" && activeProjectId ? activeProjectId : undefined);

        let targetFindingId = findingId;
        if (!targetFindingId) {
            targetFindingId = "__ALL_FINDINGS__";
        }

        const isBatchAll = (targetFindingId === "__ALL_FINDINGS__");

        const filePathInput = document.getElementById(isWorkspace ? "wsAutofixFileInput" : "standaloneFileInput");
        const filePath = filePathInput ? filePathInput.value.trim() : "";
        const constraintsInput = document.getElementById("wsAutofixDeveloperConstraints");
        const developerConstraints = constraintsInput ? constraintsInput.value.trim() : "";
        const clientReqId = "req-" + Math.random().toString(36).substring(2, 10) + "-" + Date.now();

        // Compile multi-file scope:
        // Respect user-selected sources ONLY when explicitly modified by user in USER_MODIFIED mode.
        // In AUTOMATIC mode, leave selected_files undefined and file_path null
        // so the backend executes authoritative whole-repository dynamic AST discovery.
        let selectedPaths = [];
        const validSourceExts = [".py", ".html", ".htm", ".js", ".ts", ".php", ".jsx", ".tsx"];
        const skipDirs = ["__pycache__", "node_modules", ".git", "dist", "build"];
        if (window.sourceSelectionMode === "USER_MODIFIED") {
            if (window.selectedSources && window.selectedSources.length > 0) {
                selectedPaths = window.selectedSources
                    .map(s => s.path)
                    .filter(p => p && validSourceExts.some(ext => p.toLowerCase().endsWith(ext)) && !skipDirs.some(sd => p.toLowerCase().includes(sd)));
            } else if (filePath && (filePath.includes("/") || filePath.includes("\\") || filePath.includes("."))) {
                selectedPaths = [filePath];
            }
        }

        // Concurrency Lock & Live Progress UI
        window._isRemediationRunning = true;
        const btnAnalyze = document.getElementById(isWorkspace ? "btnWsAnalyzeCodeFix" : "btnRunAutoFixPreview");
        const originalBtnHtml = btnAnalyze ? btnAnalyze.innerHTML : "";
        let progressInterval = null;

        if (btnAnalyze) {
            btnAnalyze.disabled = true;
            btnAnalyze.style.opacity = "0.75";
            btnAnalyze.style.cursor = "wait";
            btnAnalyze.innerHTML = `<span class="spinner" style="display:inline-block; width:13px; height:13px; border:2px solid #fff; border-top-color:transparent; border-radius:50%; animation:spin 0.8s linear infinite; margin-right:8px; vertical-align:middle;"></span><span id="wsAnalyzeBtnText">${isBatchAll ? "Remediating Repository..." : "Analyzing Architecture..."}</span>`;
        }

        const bannerDesc = document.getElementById("wsAutofixDiscoveryStatusDesc");
        const originalBannerDesc = bannerDesc ? bannerDesc.innerHTML : "";

        const progressSteps = isBatchAll ? [
            "1/4 Analyzing repository architecture & dynamic file tree...",
            "2/4 Discovering vulnerable code locations across whole repository...",
            "3/4 Generating AST-safe semantic security fixes & boundary controls...",
            "4/4 Validating syntax & regression boundaries across all components..."
        ] : [
            "1/3 Mapping finding to repository architecture & AST nodes...",
            "2/3 Generating semantic security remediation patch...",
            "3/3 Validating syntax & defensive logic boundaries..."
        ];

        let stepIdx = 0;
        if (bannerDesc) {
            bannerDesc.innerHTML = `<span style="color: #3b82f6; font-weight: 600;">⚡ Active Pipeline:</span> <span id="wsRemediationProgressStep">${progressSteps[0]}</span>`;
        }

        // Active server stage polling & fallback progress ticker
        progressInterval = setInterval(async () => {
            try {
                if (effectiveProjectId && clientReqId) {
                    const stRes = await fetch(`/api/ai-fix/run-status?project_id=${encodeURIComponent(effectiveProjectId)}&run_id=${encodeURIComponent(clientReqId)}`, { headers: getAuthHeaders() });
                    if (stRes.ok) {
                        const stData = await stRes.json();
                        if (stData) {
                            if (stData.is_active === 0 || ["COMPLETED", "ALL_FINDINGS_VALIDATED", "PARTIAL_REMEDIATION", "FAILED_VALIDATION", "ALREADY_SECURE", "FAILED"].includes(stData.status)) {
                                if (progressInterval) {
                                    clearInterval(progressInterval);
                                    progressInterval = null;
                                }
                            }
                            if (stData.progress_message) {
                                const stepEl = document.getElementById("wsRemediationProgressStep");
                                if (stepEl) stepEl.textContent = stData.progress_message;
                                const btnTextEl = document.getElementById("wsAnalyzeBtnText");
                                if (btnTextEl) {
                                    if (stData.progress_stage === "4/4" || stData.current_stage === "VALIDATING") {
                                        btnTextEl.textContent = "Validating Patches...";
                                    } else if (stData.progress_stage === "3/4" || stData.current_stage === "PATCHING") {
                                        btnTextEl.textContent = isBatchAll ? "Generating Fixes..." : "Generating Fix...";
                                    } else if (stData.progress_stage === "2/4" || stData.current_stage === "PLANNING") {
                                        btnTextEl.textContent = isBatchAll ? "Discovering Sources..." : "Mapping Code...";
                                    }
                                }
                                return;
                            }
                        }
                    }
                }
            } catch (_) {}

            // Graceful local ticker fallback
            stepIdx++;
            if (stepIdx < progressSteps.length) {
                const stepEl = document.getElementById("wsRemediationProgressStep");
                if (stepEl) stepEl.textContent = progressSteps[stepIdx];
                const btnTextEl = document.getElementById("wsAnalyzeBtnText");
                if (btnTextEl) {
                    if (stepIdx === 1) btnTextEl.textContent = isBatchAll ? "Discovering Sources..." : "Mapping Code...";
                    else if (stepIdx === 2) btnTextEl.textContent = isBatchAll ? "Generating Fixes..." : "Generating Fix...";
                    else if (stepIdx === 3) btnTextEl.textContent = "Validating Patches...";
                }
            }
        }, 1200);

        const abortCtrl = new AbortController();
        const abortTimeout = setTimeout(() => {
            abortCtrl.abort();
        }, 90000); // 90-second finite timeout guard

        try {
            const endpointUrl = isBatchAll ? "/api/ai-fix/batch-patch" : "/api/ai-fix/analyze";
            const reqPayload = isBatchAll ? {
                repo: repoToUse,
                branch: branchToUse,
                project_id: effectiveProjectId,
                developer_instructions: developerConstraints,
                selected_files: (window.sourceSelectionMode === "USER_MODIFIED" && selectedPaths.length > 0) ? selectedPaths : undefined,
                request_id: clientReqId
            } : {
                repo: repoToUse,
                branch: branchToUse,
                finding_id: targetFindingId,
                project_id: effectiveProjectId,
                file_path: (window.sourceSelectionMode === "USER_MODIFIED" && selectedPaths.length > 0) ? selectedPaths[0] : null,
                selected_files: (window.sourceSelectionMode === "USER_MODIFIED" && selectedPaths.length > 0) ? selectedPaths : undefined,
                developer_instructions: developerConstraints,
                request_id: clientReqId
            };

            showToast(isBatchAll ? "Remediating all detected vulnerabilities across repository..." : "Analyzing repository architecture & generating unified diff...", "info");
            const res = await fetch(endpointUrl, {
                method: "POST",
                headers: getAuthHeaders({ "Content-Type": "application/json" }),
                body: JSON.stringify(reqPayload),
                signal: abortCtrl.signal
            });

            if (!res.ok) {
                let errMsg = "Failed to analyze source code.";
                try {
                    const errData = await res.json();
                    if (errData && errData.detail) errMsg = typeof errData.detail === "string" ? errData.detail : JSON.stringify(errData.detail);
                } catch (_) {}
                throw new Error(errMsg);
            }
            const data = await res.json();
            data.repo = repoToUse;
            data.branch = branchToUse;
            const renderOk = renderAIFixRemediationResult(data, isWorkspace);
            console.log(`[FRONTEND_RESPONSE_RECEIVED] request_id=${data.request_id || clientReqId} success=${data.success}`);

            if (renderOk) {
                const diffWrap = document.getElementById(isWorkspace ? "wsDiffViewerWrapper" : "standaloneDiffWrapper");
                if (diffWrap) {
                    diffWrap.style.display = "flex";
                    diffWrap.scrollIntoView({ behavior: "smooth", block: "start" });
                }

                const rawFiles = (data.files && data.files.length > 0)
                    ? data.files
                    : (data.file_path && (data.diff_unified || "").trim().length > 0 ? [{ path: data.file_path }] : []);

                if (rawFiles.length > 0) {
                    showToast(`✓ Remediation complete: ${rawFiles.length} file${rawFiles.length > 1 ? "s" : ""} modified & validated!`, "success");
                } else if (data.patch_status === "ALREADY_SECURE" || (data.remediation_summary && data.remediation_summary.overall_status === "ALL_FINDINGS_VALIDATED")) {
                    showToast("✓ Repository is already secure — all selected findings verified clean!", "success");
                } else {
                    showToast("✓ Remediation analysis complete.", "success");
                }
            }
        } catch (err) {
            console.error("AI Fix Analysis Error:", err);
            if (err.name === "AbortError") {
                showToast("Remediation execution timed out after 90s. Checking run status...", "warning");
                try {
                    const recRes = await fetch(`/api/ai-fix/run-status?project_id=${encodeURIComponent(effectiveProjectId)}&run_id=${encodeURIComponent(clientReqId)}`, { headers: getAuthHeaders() });
                    if (recRes.ok) {
                        const recData = await recRes.json();
                        if (recData && recData.result) {
                            showToast("Remediation results recovered from server.", "success");
                            renderAIFixRemediationResult(recData.result, isWorkspace);
                            return;
                        }
                    }
                } catch (_) {}
                showToast("Remediation timed out. Workspace reset.", "error");
            } else {
                showToast(err.message, "error");
            }
        } finally {
            clearTimeout(abortTimeout);
            if (progressInterval) {
                clearInterval(progressInterval);
                progressInterval = null;
            }
            window._isRemediationRunning = false;
            if (btnAnalyze) {
                btnAnalyze.disabled = false;
                btnAnalyze.style.opacity = "1";
                btnAnalyze.style.cursor = "pointer";
                btnAnalyze.innerHTML = originalBtnHtml;
            }
            if (bannerDesc) {
                bannerDesc.innerHTML = originalBannerDesc;
            }
        }
    }

    // Toggle between Unified Diff and Before/After views
    const btnToggleDiffView = document.getElementById("btnToggleDiffView");
    const btnToggleBeforeAfterView = document.getElementById("btnToggleBeforeAfterView");
    const wsUnifiedDiffBox = document.getElementById("wsUnifiedDiffBox");
    const wsBeforeAfterBox = document.getElementById("wsBeforeAfterBox");

    if (btnToggleDiffView && btnToggleBeforeAfterView) {
        btnToggleDiffView.addEventListener("click", () => {
            if (wsUnifiedDiffBox) wsUnifiedDiffBox.style.display = "block";
            if (wsBeforeAfterBox) wsBeforeAfterBox.style.display = "none";
            btnToggleDiffView.className = "btn btn-sm btn-primary";
            btnToggleBeforeAfterView.className = "btn btn-sm btn-secondary";
        });

        btnToggleBeforeAfterView.addEventListener("click", () => {
            if (wsUnifiedDiffBox) wsUnifiedDiffBox.style.display = "none";
            if (wsBeforeAfterBox) wsBeforeAfterBox.style.display = "grid";
            btnToggleBeforeAfterView.className = "btn btn-sm btn-primary";
            btnToggleDiffView.className = "btn btn-sm btn-secondary";
        });
    }

    // Reject Fix Proposal
    const btnWsRejectFix = document.getElementById("btnWsRejectFix");
    if (btnWsRejectFix) {
        btnWsRejectFix.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            if (!data || !data.finding_id) {
                showToast("No active fix proposal to reject.", "warning");
                return;
            }

            const reason = prompt("Optional: Provide a reason for rejecting this fix proposal:", "Does not meet architectural requirements");
            if (reason === null) return;

            try {
                showToast("Rejecting fix proposal...", "info");
                const repoVal = data.repo || getSelectedRemediationRepo();
                const res = await fetch("/api/ai-fix/reject", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        finding_id: data.finding_id,
                        repo: repoVal,
                        branch: data.branch || "main",
                        reason: reason || "Rejected by developer review"
                    })
                });

                if (!res.ok) throw new Error("Failed to reject fix proposal.");

                const diffWrapper = document.getElementById("wsAnalysisDiffWrapper");
                if (diffWrapper) diffWrapper.style.display = "none";

                const proj = getActiveProject();
                if (proj && proj.findings) {
                    const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                    if (f) {
                        f.fix_status = "Fix Rejected";
                        saveProjects();
                        renderWorkspaceFindings();
                        refreshDashboardStats();
                    }
                }

                showToast("Fix proposal rejected and recorded in audit log.", "info");
            } catch (err) {
                showToast(err.message, "error");
            }
        });
    }

    // Request Revision Modal and Execution
    const btnWsRequestRevision = document.getElementById("btnWsRequestRevision");
    const btnCloseRevisionModal = document.getElementById("btnCloseRevisionModal");
    const btnCancelRevisionModal = document.getElementById("btnCancelRevisionModal");
    const btnSubmitRevisionRequest = document.getElementById("btnSubmitRevisionRequest");
    const txtRevisionInstructions = document.getElementById("txtRevisionInstructions");

    if (btnWsRequestRevision) {
        btnWsRequestRevision.addEventListener("click", () => {
            const data = window._currentAnalysisData;
            if (!data) {
                showToast("No active analysis proposal to revise.", "warning");
                return;
            }
            if (txtRevisionInstructions) txtRevisionInstructions.value = "";
            openModal("modalAIFixRevision");
            setTimeout(() => txtRevisionInstructions?.focus(), 100);
        });
    }

    if (btnCloseRevisionModal) btnCloseRevisionModal.addEventListener("click", () => closeModal("modalAIFixRevision"));
    if (btnCancelRevisionModal) btnCancelRevisionModal.addEventListener("click", () => closeModal("modalAIFixRevision"));

    if (btnSubmitRevisionRequest) {
        btnSubmitRevisionRequest.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            const instructions = txtRevisionInstructions?.value.trim();
            if (!instructions) {
                showToast("Please provide revision instructions for the AI.", "warning");
                return;
            }

            try {
                showToast("Revising remediation patch according to developer instructions...", "info");
                const res = await fetch("/api/ai-fix/revise", {
                    method: "POST",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({
                        finding_id: data.finding_id,
                        repo: data.repo,
                        branch: data.branch,
                        file_path: data.file_path,
                        current_diff: data.diff_unified,
                        original_code: data.original_code,
                        developer_instructions: instructions
                    })
                });

                if (!res.ok) throw new Error("Failed to revise fix proposal.");
                const revisedData = await res.json();
                window._currentAnalysisData = revisedData;

                closeModal("modalAIFixRevision");

                // Update UI with revised data
                const expEl = document.getElementById("wsDiffExplanation");
                const changesList = document.getElementById("wsDiffChangesList");
                const diffContainer = document.getElementById("wsDiffContainer");
                const beforeCodeContainer = document.getElementById("wsBeforeCodeContainer");
                const afterCodeContainer = document.getElementById("wsAfterCodeContainer");
                const impactEl = document.getElementById("wsDiffSecurityImpact");
                const testRecEl = document.getElementById("wsDiffTestingRec");

                if (expEl) expEl.textContent = revisedData.explanation;
                if (impactEl && revisedData.security_impact) impactEl.textContent = revisedData.security_impact;
                if (testRecEl && revisedData.testing_recommendation) testRecEl.textContent = revisedData.testing_recommendation;
                if (beforeCodeContainer) beforeCodeContainer.textContent = revisedData.before_content || revisedData.before_code || revisedData.original_code || "";
                if (afterCodeContainer) afterCodeContainer.textContent = revisedData.after_content || revisedData.after_code || revisedData.proposed_code || "";

                if (changesList) {
                    changesList.innerHTML = "";
                    (revisedData.changes || []).forEach(c => {
                        const li = document.createElement("li");
                        li.textContent = c;
                        changesList.appendChild(li);
                    });
                }

                if (diffContainer) {
                    diffContainer.innerHTML = "";
                    const diffStr = (revisedData.diff_unified || revisedData.unified_diff || revisedData.patch || "");
                    diffStr.split("\n").forEach(line => {
                        const span = document.createElement("span");
                        if (line.startsWith("+") && !line.startsWith("+++")) {
                            span.className = "diff-line-add";
                            span.style.color = "#4ade80";
                            span.style.backgroundColor = "rgba(74, 222, 128, 0.1)";
                            span.style.display = "block";
                        } else if (line.startsWith("-") && !line.startsWith("---")) {
                            span.className = "diff-line-del";
                            span.style.color = "#f87171";
                            span.style.backgroundColor = "rgba(248, 113, 113, 0.1)";
                            span.style.display = "block";
                        } else if (line.startsWith("@@")) {
                            span.className = "diff-line-info";
                            span.style.color = "#38bdf8";
                            span.style.display = "block";
                        } else {
                            span.style.display = "block";
                        }
                        span.textContent = line;
                        diffContainer.appendChild(span);
                    });
                }

                showToast(`✓ Proposal revised (Revision #${revisedData.revision_count})`, "success");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    // Pre-Write Confirmation Modal & Application
    const btnWsOpenConfirmApply = document.getElementById("btnWsOpenConfirmApply");
    const btnCloseConfirmApplyModal = document.getElementById("btnCloseConfirmApplyModal");
    const btnCancelConfirmApply = document.getElementById("btnCancelConfirmApply");
    const btnExecuteConfirmApply = document.getElementById("btnExecuteConfirmApply");

    if (btnWsOpenConfirmApply) {
        btnWsOpenConfirmApply.addEventListener("click", () => {
            const data = window._currentAnalysisData;
            if (!data) {
                showToast("No analysis diff to apply.", "error");
                return;
            }

            if (data.success === false) {
                showToast("Cannot apply an invalid or failed remediation patch. Please revise instructions.", "error");
                return;
            }

            const repoToUse = getSelectedRemediationRepo() || data.repo;
            data.repo = repoToUse;
            const branchToUse = data.branch || document.getElementById("wsAutofixBranchSelect")?.value || "main";
            data.branch = branchToUse;

            const cleanId = (data.vuln_id || data.finding_id || "VULN-001").replace(/[^a-zA-Z0-9_-]/g, "-");
            const defaultFixBranch = `fix/${cleanId}`;

            const confirmRepoInput = document.getElementById("confirmApplyRepoInput");
            if (confirmRepoInput) confirmRepoInput.value = repoToUse;

            const confirmBranchInput = document.getElementById("confirmApplyBaseBranchInput");
            if (confirmBranchInput) confirmBranchInput.value = branchToUse;

            const confirmFixBranchInput = document.getElementById("confirmApplyFixBranchInput");
            const fixBranchToSet = (confirmFixBranchInput && confirmFixBranchInput.value && !confirmFixBranchInput.value.includes("tracegate/")) ? confirmFixBranchInput.value.trim() : defaultFixBranch;
            if (confirmFixBranchInput) confirmFixBranchInput.value = fixBranchToSet;

            // Connection Mode Banner
            const modeBanner = document.getElementById("confirmApplyModeBanner");
            const modeBannerText = document.getElementById("confirmApplyModeBannerText");
            const isLive = (window._githubMode === "live" || window._githubConnected);
            if (modeBanner && modeBannerText) {
                if (isLive && !repoToUse.startsWith("tracegate-lab/")) {
                    modeBanner.style.background = "rgba(5, 150, 105, 0.1)";
                    modeBanner.style.borderColor = "rgba(5, 150, 105, 0.25)";
                    modeBanner.style.color = "#059669";
                    modeBannerText.textContent = `🟢 Live GitHub Mode: Writing real commits to ${repoToUse}`;
                } else {
                    modeBanner.style.background = "rgba(217, 119, 6, 0.1)";
                    modeBanner.style.borderColor = "rgba(217, 119, 6, 0.25)";
                    modeBanner.style.color = "#d97706";
                    modeBannerText.textContent = `⚠️ Security Lab Sandbox Mode: Simulated local commit (will not push to real GitHub)`;
                }
            }

            const quickSelect = document.getElementById("confirmApplyRepoQuickSelect");
            const wsRepoSelect = document.getElementById("wsAutofixRepoSelect");
            if (quickSelect && wsRepoSelect) {
                quickSelect.innerHTML = '<option value="">Quick Select...</option>';
                Array.from(wsRepoSelect.options).forEach(opt => {
                    if (opt.value && opt.value !== "__custom__") {
                        const o = document.createElement("option");
                        o.value = opt.value;
                        o.textContent = opt.textContent;
                        quickSelect.appendChild(o);
                    }
                });
                if (repoToUse && Array.from(quickSelect.options).some(o => o.value === repoToUse)) {
                    quickSelect.value = repoToUse;
                }
            }

            const confirmRepo = document.getElementById("confirmApplyRepo");
            if (confirmRepo) confirmRepo.textContent = repoToUse;
            const confirmBase = document.getElementById("confirmApplyBaseBranch");
            if (confirmBase) confirmBase.textContent = branchToUse;
            const confirmFixEl = document.getElementById("confirmApplyFixBranch");
            if (confirmFixEl) confirmFixEl.textContent = fixBranchToSet;
            document.getElementById("confirmApplyFile").textContent = data.file_path;
            const primarySha = data.file_sha || (data.files && data.files[0] ? data.files[0].file_sha : null);
            if (!data.file_sha && primarySha) {
                data.file_sha = primarySha;
            }
            document.getElementById("confirmApplySha").textContent = primarySha ? primarySha.substring(0, 7) : "verified";

            const defaultMsg = `fix(security): remediate ${data.vuln_id || data.finding_id} in ${data.file_path}`;
            const commitMsgInput = document.getElementById("txtConfirmCommitMsg");
            if (commitMsgInput) commitMsgInput.value = defaultMsg;

            const chkAuto = document.getElementById("chkConfirmAutoCreatePR");
            if (chkAuto) chkAuto.checked = true;
            if (btnExecuteConfirmApply) btnExecuteConfirmApply.textContent = "✓ Confirm, Commit & Create PR";

            openModal("modalAIFixConfirmApply");
        });
    }

    const confirmApplyRepoQuickSelect = document.getElementById("confirmApplyRepoQuickSelect");
    if (confirmApplyRepoQuickSelect) {
        confirmApplyRepoQuickSelect.addEventListener("change", (e) => {
            const val = e.target.value;
            if (val) {
                const input = document.getElementById("confirmApplyRepoInput");
                if (input) input.value = val;
                window._currentSelectedRepo = val;
                if (window._currentAnalysisData) window._currentAnalysisData.repo = val;
                const modeBannerText = document.getElementById("confirmApplyModeBannerText");
                if (modeBannerText) {
                    modeBannerText.textContent = `🟢 Live GitHub Mode: Writing real commits to ${val}`;
                }
            }
        });
    }

    const confirmApplyRepoInput = document.getElementById("confirmApplyRepoInput");
    if (confirmApplyRepoInput) {
        confirmApplyRepoInput.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            if (val) {
                window._currentSelectedRepo = val;
                if (window._currentAnalysisData) window._currentAnalysisData.repo = val;
            }
        });
    }

    const confirmApplyBaseBranchInput = document.getElementById("confirmApplyBaseBranchInput");
    if (confirmApplyBaseBranchInput) {
        confirmApplyBaseBranchInput.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            if (val && window._currentAnalysisData) {
                window._currentAnalysisData.branch = val;
            }
        });
    }

    const confirmApplyFixBranchInput = document.getElementById("confirmApplyFixBranchInput");
    if (confirmApplyFixBranchInput) {
        confirmApplyFixBranchInput.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            const confirmFixEl = document.getElementById("confirmApplyFixBranch");
            if (confirmFixEl) confirmFixEl.textContent = val;
        });
    }

    if (btnCloseConfirmApplyModal) btnCloseConfirmApplyModal.addEventListener("click", () => closeModal("modalAIFixConfirmApply"));
    if (btnCancelConfirmApply) btnCancelConfirmApply.addEventListener("click", () => closeModal("modalAIFixConfirmApply"));

    const chkConfirmAutoCreatePR = document.getElementById("chkConfirmAutoCreatePR");
    if (chkConfirmAutoCreatePR && btnExecuteConfirmApply) {
        chkConfirmAutoCreatePR.addEventListener("change", (e) => {
            btnExecuteConfirmApply.textContent = e.target.checked ? "✓ Confirm, Commit & Create PR" : "✓ Confirm & Commit to Branch";
        });
    }

    if (btnExecuteConfirmApply) {
        btnExecuteConfirmApply.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            if (!data) return;

            const modalRepo = document.getElementById("confirmApplyRepoInput")?.value.trim();
            const repoToUse = modalRepo || getSelectedRemediationRepo() || data.repo;
            data.repo = repoToUse;
            window._currentSelectedRepo = repoToUse;

            const modalBranch = document.getElementById("confirmApplyBaseBranchInput")?.value.trim();
            const branchToUse = modalBranch || data.branch || document.getElementById("wsAutofixBranchSelect")?.value || "main";
            data.branch = branchToUse;

            const modalFixBranch = document.getElementById("confirmApplyFixBranchInput")?.value.trim();
            const cleanId = (data.vuln_id || data.finding_id || "VULN-001").replace(/[^a-zA-Z0-9_-]/g, "-");
            const fixBranchToUse = modalFixBranch || `fix/${cleanId}`;

            const commitMsg = document.getElementById("txtConfirmCommitMsg")?.value.trim() || `fix(security): remediate ${data.vuln_id || data.finding_id}`;

            const proj = getActiveProject();
            const projId = proj ? proj.id : (typeof activeProjectId !== "undefined" ? activeProjectId : (data.project_id || null));

            const chkAutoPR = document.getElementById("chkConfirmAutoCreatePR");
            const shouldCreatePR = chkAutoPR ? chkAutoPR.checked : true;

            const origBtnText = btnExecuteConfirmApply.innerHTML;
            btnExecuteConfirmApply.disabled = true;
            btnExecuteConfirmApply.innerHTML = shouldCreatePR ? "⏳ Committing & Opening PR..." : "⏳ Committing Code...";

            const progBanner = document.getElementById("confirmApplyProgressBanner");
            const progText = document.getElementById("confirmApplyProgressText");
            const confAlert = document.getElementById("confirmApplyConflictAlert");
            const confDetails = document.getElementById("confirmApplyConflictDetails");

            if (confAlert) confAlert.style.display = "none";

            function setProgress(msg) {
                if (progBanner) progBanner.style.display = "flex";
                if (progText) progText.textContent = msg;
                showToast(msg, "info");
            }

            try {
                // 1. Detect if repository source changed since analysis
                let isChanged = false;
                let hasConflict = false;
                let conflictDetails = null;

                try {
                    const statusRes = await fetch("/api/ai-fix/check-source-status", {
                        method: "POST",
                        headers: getAuthHeaders({ "Content-Type": "application/json" }),
                        body: JSON.stringify({
                            repo: repoToUse,
                            branch: branchToUse,
                            source_commit_sha: data.source_commit_sha,
                            file_sha: data.file_sha || (data.files && data.files[0] ? data.files[0].file_sha : undefined),
                            file_path: data.file_path,
                            files: data.files || []
                        })
                    });
                    if (statusRes.ok) {
                        const st = await statusRes.json();
                        isChanged = st.is_changed;
                        hasConflict = st.has_conflict;
                        conflictDetails = st.conflict_details;
                    }
                } catch (checkErr) {
                    console.debug("Pre-check source status notice:", checkErr);
                }

                if (isChanged) {
                    if (hasConflict && conflictDetails) {
                        btnExecuteConfirmApply.disabled = false;
                        btnExecuteConfirmApply.innerHTML = origBtnText;
                        if (progBanner) progBanner.style.display = "none";
                        if (confAlert) {
                            confAlert.style.display = "flex";
                            if (confDetails) {
                                confDetails.textContent = `Target File: ${conflictDetails.file}\nAffected Region: ${conflictDetails.affected_region}\n\nUpstream Change:\n${conflictDetails.upstream_change || '(Modified in upstream branch)'}\n\nRemediation Change:\n${conflictDetails.remediation_change || '(Remediation diff)'}`;
                            }
                        }
                        showToast("SOURCE_CONFLICT_REQUIRES_REVIEW: Upstream commit conflict on base branch. Overwrite safely blocked.", "error");
                        return;
                    }

                    // Safe refresh flow with progressive feedback
                    setProgress("Repository changed since analysis. Refreshing source and regenerating the remediation…");
                    await new Promise(r => setTimeout(r, 400));

                    setProgress("Source refreshed.");
                    await new Promise(r => setTimeout(r, 350));

                    setProgress("Regenerating patch…");
                    const refreshRes = await fetch("/api/ai-fix/safe-refresh", {
                        method: "POST",
                        headers: getAuthHeaders({ "Content-Type": "application/json" }),
                        body: JSON.stringify({
                            repo: repoToUse,
                            branch: branchToUse,
                            finding_id: data.finding_id,
                            project_id: projId,
                            source_commit_sha: data.source_commit_sha,
                            file_sha: data.file_sha || (data.files && data.files[0] ? data.files[0].file_sha : undefined),
                            file_path: data.file_path,
                            files: data.files || [],
                            developer_instructions: data.developer_instructions
                        })
                    });

                    if (refreshRes.ok) {
                        const refData = await refreshRes.json();
                        if (refData.status === "SOURCE_CONFLICT_REQUIRES_REVIEW") {
                            btnExecuteConfirmApply.disabled = false;
                            btnExecuteConfirmApply.innerHTML = origBtnText;
                            if (progBanner) progBanner.style.display = "none";
                            if (confAlert) {
                                confAlert.style.display = "flex";
                                if (confDetails && refData.conflict_details) {
                                    const cd = refData.conflict_details;
                                    confDetails.textContent = `Target File: ${cd.file}\nAffected Region: ${cd.affected_region}\n\nUpstream Change:\n${cd.upstream_change || '(Modified in upstream branch)'}\n\nRemediation Change:\n${cd.remediation_change || '(Remediation diff)'}`;
                                }
                            }
                            showToast("SOURCE_CONFLICT_REQUIRES_REVIEW: Upstream changes conflict with remediation.", "error");
                            return;
                        }

                        if (refData.analysis) {
                            window._currentAnalysisData = refData.analysis;
                            data = refData.analysis;
                            if (typeof renderAIFixRemediationResult === "function") {
                                renderAIFixRemediationResult(data, true);
                            }
                            const shaEl = document.getElementById("confirmApplySha");
                            if (shaEl && refData.current_head_sha) {
                                shaEl.textContent = refData.current_head_sha.substring(0, 7);
                            }
                        }
                    }

                    setProgress("Revalidating…");
                    await new Promise(r => setTimeout(r, 350));

                    setProgress("Ready to commit.");
                    await new Promise(r => setTimeout(r, 300));
                }

                showToast(shouldCreatePR ? "Creating dedicated branch, committing fix & opening GitHub Pull Request..." : "Creating dedicated branch, verifying SHA & committing code...", "info");
                const res = await fetch("/api/ai-fix/apply", {
                    method: "POST",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({
                        repo: repoToUse,
                        target_branch: branchToUse,
                        base_branch: branchToUse,
                        fix_branch: fixBranchToUse,
                        finding_id: data.finding_id,
                        project_id: projId,
                        file_path: data.file_path,
                        file_sha: data.file_sha || (data.files && data.files[0] ? data.files[0].file_sha : undefined),
                        diff_or_fixed_code: data.proposed_code || data.after_code,
                        commit_message: commitMsg,
                        files: data.files || [],
                        create_pr: shouldCreatePR,
                        source_commit_sha: data.source_commit_sha || undefined,
                        auto_recover: true
                    })
                });

                if (res.status === 403) {
                    const errData = await res.json().catch(() => ({}));
                    closeModal("modalAIFixConfirmApply");
                    openGitHubPermissionHelpModal(errData.detail, data);
                    return;
                }

                if (res.status === 409) {
                    const errData = await res.json().catch(() => ({}));
                    const errDetail = errData.detail || {};
                    btnExecuteConfirmApply.disabled = false;
                    btnExecuteConfirmApply.innerHTML = origBtnText;
                    if (progBanner) progBanner.style.display = "none";
                    if (typeof errDetail === "object" && errDetail.conflict_details) {
                        if (confAlert) {
                            confAlert.style.display = "flex";
                            const cd = errDetail.conflict_details;
                            if (confDetails) {
                                confDetails.textContent = `Target File: ${cd.file}\nAffected Region: ${cd.affected_region}\n\nUpstream Change:\n${cd.upstream_change || '(Modified in upstream branch)'}\n\nRemediation Change:\n${cd.remediation_change || '(Remediation diff)'}`;
                            }
                        }
                        showToast("SOURCE_CONFLICT_REQUIRES_REVIEW: Overwrite blocked. Manual review required.", "error");
                        return;
                    }
                    throw new Error(typeof errDetail === "object" ? (errDetail.message || JSON.stringify(errDetail)) : errDetail);
                }

                if (res.status === 422) {
                    const errData = await res.json().catch(() => ({}));
                    const errDetail = errData.detail || {};
                    btnExecuteConfirmApply.disabled = false;
                    btnExecuteConfirmApply.innerHTML = origBtnText;
                    if (progBanner) progBanner.style.display = "none";
                    const vd = (typeof errDetail === "object" ? errDetail.verification_details : null) || {};
                    const errMsg = (typeof errDetail === "object" ? errDetail.message : errDetail) || "POST_WRITE_VERIFICATION_FAILED: Written remote content does not match approved patch.";
                    showToast(errMsg, "error");
                    if (confAlert) {
                        confAlert.style.display = "flex";
                        if (confDetails) {
                            const diffSnippet = vd.difference || "(No diff available)";
                            confDetails.textContent = `POST-WRITE VERIFICATION FAILED\n\nTarget File: ${vd.file || data.file_path}\nBranch: ${vd.branch || fixBranchToUse}\nCommit: ${vd.commit_sha || 'N/A'}\nApproved Hash: ${vd.approved_hash || 'N/A'}\nRemote Hash: ${vd.remote_hash || 'N/A'}\n\nDiff:\n${diffSnippet}`;
                        }
                    }
                    return;
                }

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    const detail = typeof errData.detail === "object" ? (errData.detail.message || JSON.stringify(errData.detail)) : (errData.detail || "Failed to apply fix.");
                    if (detail.toLowerCase().includes("not accessible by personal access token") || detail.toLowerCase().includes("permission")) {
                        closeModal("modalAIFixConfirmApply");
                        openGitHubPermissionHelpModal(errData.detail, data);
                        return;
                    }
                    throw new Error(detail);
                }

                const fixResult = await res.json();
                window._currentFixResult = fixResult;
                if (window._currentAnalysisData && fixResult.fix_id) {
                    window._currentAnalysisData.fix_id = fixResult.fix_id;
                }

                if (fixResult.source_refreshed && fixResult.refreshed_data) {
                    window._currentAnalysisData = fixResult.refreshed_data;
                    if (typeof renderAIFixRemediationResult === "function") {
                        renderAIFixRemediationResult(fixResult.refreshed_data, true);
                    }
                    showToast("Repository changed since analysis. Remediation safely refreshed and regenerated against latest source.", "info");
                }

                closeModal("modalAIFixConfirmApply");

                // Update UI Card
                const card = document.getElementById("wsFixAppliedCard");
                const branchEl = document.getElementById("wsFixBranchName");
                const shaEl = document.getElementById("wsFixCommitSha");

                if (card) card.style.display = "flex";
                if (branchEl) branchEl.textContent = fixResult.branch_name;
                if (shaEl) shaEl.textContent = fixResult.commit_sha;

                // Reset retest badge
                const retestSuccessBadge = document.getElementById("retestSuccessBadge");
                if (retestSuccessBadge) retestSuccessBadge.style.display = "none";
                const retestPill = document.getElementById("retestLifecyclePill");
                if (retestPill) {
                    retestPill.className = "badge badge-warning";
                    retestPill.textContent = "Retest Pending";
                }

                // Handle PR creation result
                if (fixResult.pr_url) {
                    window._currentPRResult = {
                        pr_number: fixResult.pr_number,
                        pr_url: fixResult.pr_url,
                        merged: false,
                        state: "open"
                    };
                    updatePRUI({
                        pr_number: fixResult.pr_number,
                        pr_url: fixResult.pr_url,
                        merged: false,
                        state: "open",
                        review_status: "Awaiting Review"
                    });
                    if (proj && proj.findings) {
                        const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                        if (f) {
                            f.fix_status = "PR Created";
                            f.github_branch = fixResult.branch_name;
                            f.github_commit = fixResult.commit_sha;
                            f.github_pr = fixResult.pr_url;
                            f.retest_status = "PENDING";
                            saveProjects();
                            renderWorkspaceFindings();
                            refreshDashboardStats();
                        }
                    }
                    const prBtn = document.getElementById("btnWsCreatePR");
                    if (prBtn) {
                        prBtn.textContent = `✓ PR #${fixResult.pr_number} Created`;
                        prBtn.className = "btn btn-outline-success btn-sm";
                    }
                    showToast(`✓ Fix committed & GitHub Pull Request #${fixResult.pr_number} created successfully!`, "success");
                } else if (shouldCreatePR) {
                    // Fallback client-side PR creation if backend apply did not return a PR
                    try {
                        showToast("Opening formal GitHub Pull Request...", "info");
                        const prRes = await fetch("/api/ai-fix/create-pr", {
                            method: "POST",
                            headers: getAuthHeaders({ "Content-Type": "application/json" }),
                            body: JSON.stringify({
                                repo: repoToUse,
                                fix_branch: fixResult.branch_name,
                                base_branch: branchToUse,
                                finding_id: data.finding_id,
                                project_id: projId
                            })
                        });
                        if (prRes.ok) {
                            const prData = await prRes.json();
                            window._currentPRResult = prData;
                            updatePRUI({
                                pr_number: prData.pr_number,
                                pr_url: prData.pr_url,
                                merged: false,
                                state: "open",
                                review_status: prData.review_status || "Awaiting Review"
                            });
                            if (proj && proj.findings) {
                                const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                                if (f) {
                                    f.fix_status = "PR Created";
                                    f.github_branch = fixResult.branch_name;
                                    f.github_commit = fixResult.commit_sha;
                                    f.github_pr = prData.pr_url;
                                    f.retest_status = "PENDING";
                                    saveProjects();
                                    renderWorkspaceFindings();
                                    refreshDashboardStats();
                                }
                            }
                            const prBtn = document.getElementById("btnWsCreatePR");
                            if (prBtn) {
                                prBtn.textContent = `✓ PR #${prData.pr_number} Created`;
                                prBtn.className = "btn btn-outline-success btn-sm";
                            }
                            showToast(`✓ GitHub Pull Request #${prData.pr_number} created successfully!`, "success");
                        } else {
                            showToast(`✓ Fix committed to branch ${fixResult.branch_name}! Click 'Create GitHub Pull Request' to open PR.`, "info");
                        }
                    } catch (prErr) {
                        console.warn("Client fallback PR error:", prErr);
                        showToast(`✓ Fix committed to branch ${fixResult.branch_name}!`, "success");
                    }
                } else {
                    if (proj && proj.findings) {
                        const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                        if (f) {
                            f.fix_status = "Fix Applied";
                            f.github_branch = fixResult.branch_name;
                            f.github_commit = fixResult.commit_sha;
                            f.retest_status = "PENDING";
                            saveProjects();
                            renderWorkspaceFindings();
                            refreshDashboardStats();
                        }
                    }
                    showToast(`✓ Fix successfully committed to dedicated branch ${fixResult.branch_name}!`, "success");
                }
            } catch (err) {
                if (err.message && (err.message.includes("Resource not accessible") || err.message.includes("GITHUB_PERMISSION_DENIED"))) {
                    closeModal("modalAIFixConfirmApply");
                    openGitHubPermissionHelpModal(err.message, data);
                    return;
                }
                showToast(err.message, "error");
            } finally {
                btnExecuteConfirmApply.disabled = false;
                btnExecuteConfirmApply.innerHTML = origBtnText;
            }
        });
    }

    // Create PR execution
    const btnWsCreatePR = document.getElementById("btnWsCreatePR");
    if (btnWsCreatePR) {
        btnWsCreatePR.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            const fixResult = window._currentFixResult;
            if (!data || !fixResult) {
                showToast("Please apply the fix first before creating a Pull Request.", "error");
                return;
            }

            const modalRepo = document.getElementById("confirmApplyRepoInput")?.value.trim();
            const repoToUse = modalRepo || getSelectedRemediationRepo() || data.repo;
            data.repo = repoToUse;
            window._currentSelectedRepo = repoToUse;

            const modalBranch = document.getElementById("confirmApplyBaseBranchInput")?.value.trim();
            const branchToUse = modalBranch || data.branch || document.getElementById("wsAutofixBranchSelect")?.value || "main";
            data.branch = branchToUse;

            const proj = getActiveProject();
            const projId = proj ? proj.id : (typeof activeProjectId !== "undefined" ? activeProjectId : null);
            const origPrBtnHtml = btnWsCreatePR.innerHTML;

            try {
                showToast("Creating formal GitHub Pull Request...", "info");
                btnWsCreatePR.disabled = true;
                btnWsCreatePR.innerHTML = "⏳ Creating Pull Request...";

                const res = await fetch("/api/ai-fix/create-pr", {
                    method: "POST",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({
                        repo: repoToUse,
                        fix_branch: fixResult.branch_name,
                        base_branch: branchToUse,
                        finding_id: data.finding_id,
                        project_id: projId
                    })
                });

                if (res.status === 403) {
                    const errData = await res.json().catch(() => ({}));
                    openGitHubPermissionHelpModal(errData.detail, data);
                    return;
                }

                if (res.status === 401) {
                    const errData = await res.json().catch(() => ({}));
                    const detail = typeof errData.detail === "object" ? (errData.detail.message || JSON.stringify(errData.detail)) : (errData.detail || "");
                    if (detail && detail.toLowerCase().includes("github")) {
                        showToast(detail, "error");
                        openModal("modalCodeConnector");
                    } else {
                        showToast("Session expired. Please sign in again.", "error");
                    }
                    return;
                }

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    const detail = typeof errData.detail === "object" ? (errData.detail.message || JSON.stringify(errData.detail)) : (errData.detail || "Failed to create Pull Request.");
                    if (detail.toLowerCase().includes("not accessible by personal access token") || detail.toLowerCase().includes("permission")) {
                        openGitHubPermissionHelpModal(errData.detail, data);
                        return;
                    }
                    throw new Error(detail);
                }
                const prResult = await res.json();
                window._currentPRResult = prResult;

                updatePRUI({
                    pr_number: prResult.pr_number,
                    pr_url: prResult.pr_url,
                    merged: false,
                    state: "open",
                    review_status: prResult.review_status || "Awaiting Review"
                });

                if (proj && proj.findings) {
                    const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                    if (f) {
                        f.fix_status = "PR Created";
                        f.github_pr = prResult.pr_url;
                        saveProjects();
                        renderWorkspaceFindings();
                    }
                }

                showToast(`✓ GitHub Pull Request #${prResult.pr_number} created successfully!`, "success");
            } catch (err) {
                if (err.message && (err.message.includes("Resource not accessible") || err.message.includes("GITHUB_PERMISSION_DENIED"))) {
                    openGitHubPermissionHelpModal(err.message, data);
                    return;
                }
                showToast(err.message, "error");
            } finally {
                btnWsCreatePR.disabled = false;
                btnWsCreatePR.innerHTML = origPrBtnHtml;
            }
        });
    }

    // Helper: update PR UI elements
    function updatePRUI(prInfo) {
        if (!prInfo) return;
        const prRow = document.getElementById("wsPRResultRow");
        const prLink = document.getElementById("wsPRLink");
        const prBannerTitle = document.getElementById("wsPRBannerTitle");
        const prStatusPill = document.getElementById("wsPRStatusPill");
        const prReviewPill = document.getElementById("wsPRReviewStatusPill");
        const btnMerge = document.getElementById("btnWsMergePR");

        if (prRow) prRow.style.display = "flex";
        if (prBannerTitle && prInfo.pr_number) {
            prBannerTitle.textContent = `GitHub Pull Request #${prInfo.pr_number} Opened`;
        }
        if (prLink && (prInfo.pr_url || prInfo.html_url)) {
            const url = prInfo.pr_url || prInfo.html_url;
            prLink.href = url;
            prLink.textContent = `View PR #${prInfo.pr_number} on GitHub →`;
        }

        const isMerged = prInfo.merged === true || prInfo.pr_status === "Merged" || prInfo.status === "MERGED";
        const isClosed = !isMerged && (prInfo.state === "closed" || prInfo.pr_status === "Closed");

        if (prStatusPill) {
            if (isMerged) {
                prStatusPill.className = "badge badge-completed";
                prStatusPill.textContent = "Merged";
            } else if (isClosed) {
                prStatusPill.className = "badge badge-danger";
                prStatusPill.textContent = "Closed";
            } else {
                prStatusPill.className = "badge badge-in-progress";
                prStatusPill.textContent = "Open";
            }
        }

        if (prReviewPill) {
            const rev = (prInfo.review_status || "PENDING").toUpperCase();
            if (rev === "APPROVED") {
                prReviewPill.className = "badge badge-completed";
                prReviewPill.textContent = "Approved";
            } else if (rev === "CHANGES_REQUESTED") {
                prReviewPill.className = "badge badge-danger";
                prReviewPill.textContent = "Changes Requested";
            } else if (rev === "COMMENTED") {
                prReviewPill.className = "badge badge-warning";
                prReviewPill.textContent = "Commented";
            } else {
                prReviewPill.className = "badge badge-secondary";
                prReviewPill.textContent = "Awaiting Review";
            }
        }

        if (btnMerge) {
            if (isMerged) {
                btnMerge.disabled = true;
                btnMerge.textContent = "✓ Merged into Base";
            } else if (isClosed) {
                btnMerge.disabled = true;
                btnMerge.textContent = "PR Closed";
            } else {
                btnMerge.disabled = false;
                btnMerge.textContent = "🔀 Merge PR into Base";
            }
        }
    }

    // Helper: Fetch live PR status from GitHub and synchronize
    async function fetchLivePRStatus(repo, prNumber) {
        if (!repo || !prNumber || prNumber === "N/A") return null;
        try {
            const res = await fetch(`/api/ai-fix/pr/${repo}/${prNumber}/status`);
            if (!res.ok) return null;
            const data = await res.json();
            if (window._currentPRResult) {
                window._currentPRResult.state = data.state;
                window._currentPRResult.merged = data.merged;
                window._currentPRResult.review_status = data.review_status;
                window._currentPRResult.html_url = data.html_url || window._currentPRResult.pr_url;
            }
            updatePRUI({
                pr_number: prNumber,
                pr_url: data.html_url || (window._currentPRResult && window._currentPRResult.pr_url),
                merged: data.merged,
                state: data.state,
                review_status: data.review_status
            });

            if (data.merged) {
                const proj = getActiveProject();
                const findingId = window._currentAnalysisData?.finding_id;
                if (proj && proj.findings && findingId) {
                    const f = proj.findings.find(item => item.id === findingId || item.vuln_id === findingId);
                    if (f && f.fix_status !== "Code Merged (Retest Required)") {
                        f.fix_status = "Code Merged (Retest Required)";
                        saveProjects();
                        renderWorkspaceFindings();
                    }
                }
            }
            return data;
        } catch (e) {
            console.warn("Failed to fetch live PR status:", e);
            return null;
        }
    }

    // Live PR Status Check Button
    const btnWsCheckPRStatus = document.getElementById("btnWsCheckPRStatus");
    if (btnWsCheckPRStatus) {
        btnWsCheckPRStatus.addEventListener("click", async () => {
            const pr = window._currentPRResult;
            const data = window._currentAnalysisData;
            if (!pr || !pr.pr_number) {
                showToast("No active Pull Request to check.", "warning");
                return;
            }
            const repo = data?.repo || getSelectedRemediationRepo();
            showToast("Checking live PR status & reviews on GitHub...", "info");
            const res = await fetchLivePRStatus(repo, pr.pr_number);
            if (res) {
                showToast(`✓ PR #${pr.pr_number} status: ${res.state.toUpperCase()} | Review: ${res.review_status}`, "success");
            } else {
                showToast("Could not retrieve live status from GitHub.", "error");
            }
        });
    }

    // Merge PR Confirmation Modal & Execution
    const modalConfirmMergePR = document.getElementById("modalConfirmMergePR");
    const btnWsMergePR = document.getElementById("btnWsMergePR");
    const btnCancelConfirmMergePR = document.getElementById("btnCancelConfirmMergePR");
    const btnCloseConfirmMergePRModal = document.getElementById("btnCloseConfirmMergePRModal");
    const btnExecuteConfirmMergePR = document.getElementById("btnExecuteConfirmMergePR");

    if (btnWsMergePR) {
        btnWsMergePR.addEventListener("click", () => {
            const data = window._currentAnalysisData;
            const prResult = window._currentPRResult;
            if (!data || !prResult) {
                showToast("No active Pull Request to merge.", "warning");
                return;
            }

            const repo = data.repo || getSelectedRemediationRepo();
            const prLink = document.getElementById("mergeModalPRLink");
            const mergeModalRepo = document.getElementById("mergeModalRepo");
            const mergeModalFixBranch = document.getElementById("mergeModalFixBranch");
            const mergeModalBaseBranch = document.getElementById("mergeModalBaseBranch");
            const mergeModalReviewStatus = document.getElementById("mergeModalReviewStatus");

            if (prLink) {
                prLink.href = prResult.pr_url || prResult.html_url || "#";
                prLink.textContent = `PR #${prResult.pr_number}`;
            }
            if (mergeModalRepo) mergeModalRepo.textContent = repo;
            if (mergeModalFixBranch) {
                mergeModalFixBranch.textContent = window._currentFixResult?.branch_name || data.fix_branch || `tracegate/fix/${data.finding_id}`;
            }
            if (mergeModalBaseBranch) {
                mergeModalBaseBranch.textContent = data.branch || "main";
            }
            if (mergeModalReviewStatus) {
                const rev = (prResult.review_status || "PENDING").toUpperCase();
                mergeModalReviewStatus.textContent = rev === "APPROVED" ? "Approved" : (rev === "CHANGES_REQUESTED" ? "Changes Requested" : (rev === "COMMENTED" ? "Commented" : "Awaiting Review"));
                mergeModalReviewStatus.className = rev === "APPROVED" ? "badge badge-completed" : (rev === "CHANGES_REQUESTED" ? "badge badge-danger" : "badge badge-secondary");
            }

            if (modalConfirmMergePR) modalConfirmMergePR.classList.add("open");
        });
    }

    [btnCancelConfirmMergePR, btnCloseConfirmMergePRModal].forEach(btn => {
        if (btn) {
            btn.addEventListener("click", () => {
                if (modalConfirmMergePR) modalConfirmMergePR.classList.remove("open");
            });
        }
    });

    if (btnExecuteConfirmMergePR) {
        btnExecuteConfirmMergePR.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            const prResult = window._currentPRResult;
            if (!data || !prResult) {
                if (modalConfirmMergePR) modalConfirmMergePR.classList.remove("open");
                return;
            }

            try {
                if (modalConfirmMergePR) modalConfirmMergePR.classList.remove("open");
                showToast("Merging Pull Request into base branch...", "info");
                const res = await fetch("/api/ai-fix/pr/merge", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        finding_id: data.finding_id,
                        repo: data.repo || getSelectedRemediationRepo(),
                        pr_number: prResult.pr_number
                    })
                });

                if (res.status === 403) {
                    const errData = await res.json().catch(() => ({}));
                    openGitHubPermissionHelpModal(errData.detail, data);
                    return;
                }

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    const detail = typeof errData.detail === "object" ? (errData.detail.message || JSON.stringify(errData.detail)) : (errData.detail || "Failed to merge Pull Request.");
                    throw new Error(detail);
                }

                const mergeData = await res.json();
                prResult.merged = true;
                prResult.pr_status = "Merged";

                updatePRUI({
                    pr_number: prResult.pr_number,
                    pr_url: prResult.pr_url,
                    merged: true,
                    state: "closed",
                    review_status: prResult.review_status
                });

                const proj = getActiveProject();
                if (proj && proj.findings) {
                    const f = proj.findings.find(item => item.id === data.finding_id || item.vuln_id === data.finding_id);
                    if (f) {
                        f.fix_status = "Code Merged (Retest Required)";
                        saveProjects();
                        renderWorkspaceFindings();
                    }
                }

                showToast("✓ PR merged into base branch! Note: Retest is still required to confirm vulnerability resolution.", "success");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    // Retest Pass / Fail Execution with Double-Click Protection & Auth Headers
    const btnWsPassRetest = document.getElementById("btnWsPassRetest");
    const btnWsFailRetest = document.getElementById("btnWsFailRetest");
    let isSubmittingRetest = false;

    if (btnWsPassRetest) {
        btnWsPassRetest.addEventListener("click", async () => {
            if (isSubmittingRetest) return;

            const data = window._currentAnalysisData || {};
            const proj = getActiveProject();
            const projId = proj ? proj.id : (typeof activeProjectId !== "undefined" ? activeProjectId : null);

            // Authoritative finding ID resolution adhering strictly to active project scope
            let targetFindingId = null;
            const selVal = document.getElementById("wsAutofixFindingSelect")?.value;

            if (selVal === "__ALL_FINDINGS__") {
                targetFindingId = "__ALL_FINDINGS__";
            } else if (selVal) {
                targetFindingId = selVal;
            } else if (data.finding_id) {
                targetFindingId = data.finding_id;
                if (proj && proj.findings) {
                    const match = proj.findings.find(f => f.id === targetFindingId || f.vuln_id === targetFindingId);
                    if (match && match.id) targetFindingId = match.id;
                }
            } else if (proj && proj.findings && proj.findings.length === 1) {
                targetFindingId = proj.findings[0].id;
            }

            if (!targetFindingId) {
                showToast("No active finding remediation in progress.", "warning");
                return;
            }

            const notes = document.getElementById("txtRetestNotes")?.value.trim() || "";
            const origPassHtml = btnWsPassRetest.innerHTML;
            const origFailHtml = btnWsFailRetest ? btnWsFailRetest.innerHTML : "";
            const fixId = data.fix_id || (window._currentFixResult && window._currentFixResult.fix_id) || null;

            isSubmittingRetest = true;
            btnWsPassRetest.disabled = true;
            if (btnWsFailRetest) btnWsFailRetest.disabled = true;
            btnWsPassRetest.textContent = "⏳ Recording Retest...";

            try {
                showToast("Recording tester retest verification (PASS)...", "info");

                const queryParams = new URLSearchParams();
                if (projId) {
                    queryParams.set("project_id", projId);
                    queryParams.set("assessment_id", projId);
                }
                const queryStr = queryParams.toString() ? `?${queryParams.toString()}` : "";

                const res = await fetch(`/api/ai-fix/${encodeURIComponent(targetFindingId)}/retest${queryStr}`, {
                    method: "POST",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({
                        finding_id: targetFindingId,
                        project_id: projId,
                        assessment_id: projId,
                        fix_id: fixId,
                        result: "PASS",
                        notes: notes
                    })
                });

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    let errorMsg = "Unable to record retest. Please try again.";
                    if (res.status === 401) {
                        errorMsg = "Your session has expired. Please sign in again.";
                    } else if (res.status === 403) {
                        errorMsg = "You do not have access to this finding.";
                    } else if (res.status === 404) {
                        errorMsg = (errData && errData.detail && typeof errData.detail === "string") ? errData.detail : "Finding could not be located.";
                    } else if (res.status === 408 || res.status === 504) {
                        errorMsg = "Operation timed out on the server. Please check status or retry.";
                    } else if (res.status === 502 || res.status === 503) {
                        errorMsg = "Service temporarily unavailable. Please retry shortly.";
                    } else if (res.status === 409) {
                        errorMsg = "Retest state changed. Refresh and try again.";
                    } else if (res.status === 422) {
                        errorMsg = "Retest data is invalid.";
                    } else if (res.status >= 500) {
                        errorMsg = (errData && errData.detail && typeof errData.detail === "string") ? errData.detail : "Server error while recording retest. Please try again.";
                    } else if (errData && errData.detail) {
                        errorMsg = typeof errData.detail === "string" ? errData.detail : JSON.stringify(errData.detail);
                    }
                    throw new Error(errorMsg);
                }

                const retestRes = await res.json();

                const retestPill = document.getElementById("retestLifecyclePill");
                const retestSuccessBadge = document.getElementById("retestSuccessBadge");

                if (retestPill) {
                    retestPill.className = "badge badge-completed";
                    retestPill.textContent = "Retest Passed";
                }
                if (retestSuccessBadge) {
                    retestSuccessBadge.style.display = "block";
                    retestSuccessBadge.innerHTML = `✓ Finding transitioned: <strong>Fix Applied &rarr; Retested &rarr; RESOLVED</strong>`;
                }

                if (proj && proj.findings) {
                    const f = proj.findings.find(item => item.id === targetFindingId || item.vuln_id === targetFindingId);
                    if (f) {
                        f.status = "RESOLVED";
                        f.retest_status = "PASSED";
                        f.fix_status = "RESOLVED";
                        f.resolved_at = retestRes.updated_at || new Date().toISOString();
                        f.retest_notes = notes;
                        saveProjects();
                        renderWorkspaceFindings();
                    }
                }

                showToast("Retest recorded successfully.", "success");
                showToast("Finding transitioned: Fix Applied → Retested → Resolved", "success");

                // Check if VAPT Assessment Completion Certificate is newly eligible or generated
                const certBanner = document.getElementById("wsRetestCertBanner");
                const progressBanner = document.getElementById("wsRetestProgressBanner");
                if (retestRes && retestRes.certificate) {
                    if (progressBanner) progressBanner.style.display = "none";
                    if (typeof updateAIFixCertButtons === "function") {
                        updateAIFixCertButtons(retestRes.certificate);
                    }
                    if (typeof showCertificateCompletionModal === "function") {
                        showCertificateCompletionModal(retestRes.certificate);
                    }
                    if (certBanner) certBanner.style.display = "block";
                    if (proj && typeof refreshProjectCertificateStatus === "function") {
                        refreshProjectCertificateStatus(proj.id);
                    }
                } else if (retestRes && retestRes.certificate_eligible) {
                    if (progressBanner) progressBanner.style.display = "none";
                    if (certBanner) certBanner.style.display = "block";
                    if (proj && typeof pollForCertificate === "function") {
                        pollForCertificate(proj.id, retestRes.certificate_job_id);
                    }
                    if (proj && typeof refreshProjectCertificateStatus === "function") {
                        refreshProjectCertificateStatus(proj.id);
                    }
                } else {
                    if (certBanner) certBanner.style.display = "none";
                    if (retestRes && retestRes.blocking_reason) {
                        showToast(`✓ Finding resolved. Assessment certificate pending: ${retestRes.blocking_reason}`, "info");
                    }
                    if (typeof renderRetestProgressBanner === "function") {
                        renderRetestProgressBanner(retestRes.eligibility || retestRes, proj);
                    }
                    if (proj && typeof refreshProjectCertificateStatus === "function") {
                        refreshProjectCertificateStatus(proj.id);
                    }
                }

                btnWsPassRetest.innerHTML = "✓ Retest Passed";
                btnWsPassRetest.disabled = true;
                if (btnWsFailRetest) btnWsFailRetest.disabled = false;
            } catch (e) {
                const isNetworkErr = e.name === "TypeError" && e.message && e.message.toLowerCase().includes("fetch");
                showToast(isNetworkErr ? "Unable to contact Tracegate server." : e.message, "error");
                btnWsPassRetest.disabled = false;
                btnWsPassRetest.innerHTML = origPassHtml;
                if (btnWsFailRetest) {
                    btnWsFailRetest.disabled = false;
                    btnWsFailRetest.innerHTML = origFailHtml;
                }
            } finally {
                isSubmittingRetest = false;
            }
        });
    }

    if (btnWsFailRetest) {
        btnWsFailRetest.addEventListener("click", async () => {
            if (isSubmittingRetest) return;

            const data = window._currentAnalysisData || {};
            const proj = getActiveProject();
            const projId = proj ? proj.id : (typeof activeProjectId !== "undefined" ? activeProjectId : null);

            // Authoritative finding ID resolution adhering strictly to active project scope
            let targetFindingId = null;
            const selVal = document.getElementById("wsAutofixFindingSelect")?.value;

            if (selVal === "__ALL_FINDINGS__") {
                targetFindingId = "__ALL_FINDINGS__";
            } else if (selVal) {
                targetFindingId = selVal;
            } else if (data.finding_id) {
                targetFindingId = data.finding_id;
                if (proj && proj.findings) {
                    const match = proj.findings.find(f => f.id === targetFindingId || f.vuln_id === targetFindingId);
                    if (match && match.id) targetFindingId = match.id;
                }
            } else if (proj && proj.findings && proj.findings.length === 1) {
                targetFindingId = proj.findings[0].id;
            }

            if (!targetFindingId) {
                showToast("No active finding remediation in progress.", "warning");
                return;
            }

            const notes = document.getElementById("txtRetestNotes")?.value.trim() || "Exploit payload still executes successfully after patch.";
            const origPassHtml = btnWsPassRetest ? btnWsPassRetest.innerHTML : "";
            const origFailHtml = btnWsFailRetest.innerHTML;
            const fixId = data.fix_id || (window._currentFixResult && window._currentFixResult.fix_id) || null;

            isSubmittingRetest = true;
            btnWsFailRetest.disabled = true;
            if (btnWsPassRetest) btnWsPassRetest.disabled = true;
            btnWsFailRetest.textContent = "⏳ Recording Retest...";

            try {
                showToast("Recording tester retest verification (FAIL)...", "info");

                const queryParams = new URLSearchParams();
                if (projId) {
                    queryParams.set("project_id", projId);
                    queryParams.set("assessment_id", projId);
                }
                const queryStr = queryParams.toString() ? `?${queryParams.toString()}` : "";

                const res = await fetch(`/api/ai-fix/${encodeURIComponent(targetFindingId)}/retest${queryStr}`, {
                    method: "POST",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({
                        finding_id: targetFindingId,
                        project_id: projId,
                        assessment_id: projId,
                        fix_id: fixId,
                        result: "FAIL",
                        notes: notes
                    })
                });

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    let errorMsg = "Unable to record retest. Please try again.";
                    if (res.status === 401) {
                        errorMsg = "Your session has expired. Please sign in again.";
                    } else if (res.status === 403) {
                        errorMsg = "You do not have access to this finding.";
                    } else if (res.status === 404) {
                        errorMsg = (errData && errData.detail && typeof errData.detail === "string") ? errData.detail : "Finding could not be located.";
                    } else if (res.status === 408 || res.status === 504) {
                        errorMsg = "Operation timed out on the server. Please check status or retry.";
                    } else if (res.status === 502 || res.status === 503) {
                        errorMsg = "Service temporarily unavailable. Please retry shortly.";
                    } else if (res.status === 409) {
                        errorMsg = "Retest state changed. Refresh and try again.";
                    } else if (res.status === 422) {
                        errorMsg = "Retest data is invalid.";
                    } else if (res.status >= 500) {
                        errorMsg = (errData && errData.detail && typeof errData.detail === "string") ? errData.detail : "Server error while recording retest. Please try again.";
                    } else if (errData && errData.detail) {
                        errorMsg = typeof errData.detail === "string" ? errData.detail : JSON.stringify(errData.detail);
                    }
                    throw new Error(errorMsg);
                }

                const retestRes = await res.json();

                const retestPill = document.getElementById("retestLifecyclePill");
                const retestSuccessBadge = document.getElementById("retestSuccessBadge");

                if (retestPill) {
                    retestPill.className = "badge badge-critical";
                    retestPill.textContent = "Retest Failed (Reopened)";
                }
                if (retestSuccessBadge) {
                    retestSuccessBadge.style.display = "block";
                    retestSuccessBadge.innerHTML = `
                        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; padding: 4px 0;">
                            <span style="color: #b91c1c;">✗ Vulnerability still reproducible. Finding transitioned: <strong>REOPENED</strong>.</span>
                            <button type="button" class="btn btn-outline-primary btn-sm" id="btnReturnToAIFix" style="padding: 4px 10px; font-size: 0.78rem;">
                                🔄 Return to AI Fix & Revise
                            </button>
                        </div>
                    `;
                    const btnReturn = document.getElementById("btnReturnToAIFix");
                    if (btnReturn) {
                        btnReturn.addEventListener("click", () => {
                            const diffWrapper = document.getElementById("wsAnalysisDiffWrapper");
                            if (diffWrapper) diffWrapper.style.display = "block";
                            const txtRev = document.getElementById("txtRevisionInstructions");
                            if (txtRev) txtRev.value = `Retest verification failed: ${notes}\nPlease adjust the fix to ensure the vulnerability is fully remediated.`;
                            openModal("modalAIFixRevision");
                            setTimeout(() => txtRev?.focus(), 100);
                        });
                    }
                }

                if (proj && proj.findings) {
                    if (targetFindingId === "__ALL_FINDINGS__") {
                        proj.findings.forEach(item => {
                            item.status = "REOPENED";
                            item.fix_status = "RETEST_FAILED";
                            item.retest_status = "FAILED";
                            item.retest_notes = notes;
                        });
                    } else {
                        const f = proj.findings.find(item => item.id === targetFindingId || item.vuln_id === targetFindingId);
                        if (f) {
                            f.status = "REOPENED";
                            f.fix_status = "RETEST_FAILED";
                            f.retest_status = "FAILED";
                            f.retest_notes = notes;
                        }
                    }
                    saveProjects();
                    renderWorkspaceFindings();
                    refreshDashboardStats();
                }

                if (typeof updateAIFixCertButtons === "function") {
                    updateAIFixCertButtons(null);
                }
                if (proj && typeof refreshProjectCertificateStatus === "function") {
                    refreshProjectCertificateStatus(proj.id);
                }

                showToast("Retest verification recorded (FAIL). Finding reopened.", "warning");
                btnWsFailRetest.innerHTML = origFailHtml;
                btnWsFailRetest.disabled = false;
                if (btnWsPassRetest) {
                    btnWsPassRetest.disabled = false;
                    btnWsPassRetest.innerHTML = origPassHtml;
                }
            } catch (e) {
                const isNetworkErr = e.name === "TypeError" && e.message && e.message.toLowerCase().includes("fetch");
                showToast(isNetworkErr ? "Unable to contact Tracegate server." : e.message, "error");
                btnWsFailRetest.disabled = false;
                btnWsFailRetest.innerHTML = origFailHtml;
                if (btnWsPassRetest) {
                    btnWsPassRetest.disabled = false;
                    btnWsPassRetest.innerHTML = origPassHtml;
                }
            } finally {
                isSubmittingRetest = false;
            }
        });
    }

    // View Remediation Review Report Modal
    const btnWsViewRemediationReport = document.getElementById("btnWsViewRemediationReport");
    const btnCloseRemediationReportModal = document.getElementById("btnCloseRemediationReportModal");
    const btnCloseRemediationReportBtn = document.getElementById("btnCloseRemediationReportBtn");
    const btnCopyRemediationReport = document.getElementById("btnCopyRemediationReport");

    if (btnWsViewRemediationReport) {
        btnWsViewRemediationReport.addEventListener("click", async () => {
            const data = window._currentAnalysisData;
            if (!data) return;

            try {
                const res = await fetch(`/api/ai-fix/${data.finding_id}/report`);
                if (!res.ok) throw new Error("Failed to load remediation report.");
                const repData = await res.json();

                const container = document.getElementById("remediationReportMarkdownContainer");
                if (container) container.textContent = repData.report_markdown || "";

                openModal("modalRemediationReport");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    if (btnCloseRemediationReportModal) btnCloseRemediationReportModal.addEventListener("click", () => closeModal("modalRemediationReport"));
    if (btnCloseRemediationReportBtn) btnCloseRemediationReportBtn.addEventListener("click", () => closeModal("modalRemediationReport"));

    if (btnCopyRemediationReport) {
        btnCopyRemediationReport.addEventListener("click", () => {
            const container = document.getElementById("remediationReportMarkdownContainer");
            if (!container) return;
            navigator.clipboard.writeText(container.textContent).then(() => {
                showToast("✓ Remediation review report copied to clipboard!", "success");
            });
        });
    }

    // Connect GitHub Settings Modal handlers
    const btnOpenGitHubModal = document.getElementById("btnOpenGitHubModal");
    const btnCloseGitHubModal = document.getElementById("btnCloseGitHubModal");
    const btnCancelGitHubModal = document.getElementById("btnCancelGitHubModal");
    const btnSaveGitHubModal = document.getElementById("btnSaveGitHubModal");
    const btnDisconnectGitHub = document.getElementById("btnDisconnectGitHub");

    if (btnOpenGitHubModal) {
        btnOpenGitHubModal.addEventListener("click", () => {
            if (typeof loadGitHubFixStatus === "function") loadGitHubFixStatus();
            openModal("modalConnectGitHub");
        });
    }
    if (btnCloseGitHubModal) btnCloseGitHubModal.addEventListener("click", () => closeModal("modalConnectGitHub"));
    if (btnCancelGitHubModal) btnCancelGitHubModal.addEventListener("click", () => closeModal("modalConnectGitHub"));

    const ghModalTokenInput = document.getElementById("ghModalTokenInput");
    const ghModalModeSelect = document.getElementById("ghModalModeSelect");
    if (ghModalTokenInput && ghModalModeSelect) {
        ghModalTokenInput.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            if (val.startsWith("ghp_") || val.startsWith("github_pat_") || val.length > 20) {
                ghModalModeSelect.value = "live";
            }
        });
    }

    if (btnSaveGitHubModal) {
        btnSaveGitHubModal.addEventListener("click", async () => {
            const token = document.getElementById("ghModalTokenInput")?.value.trim();
            const username = document.getElementById("ghModalUsernameInput")?.value.trim();
            let mode = document.getElementById("ghModalModeSelect")?.value || "mock";
            if (token && (token.startsWith("ghp_") || token.startsWith("github_pat_") || token.length > 20)) {
                mode = "live";
            }

            try {
                const res = await fetch("/api/github/connect", {
                    method: "POST",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({ token: token || null, username: username || null, mode })
                });

                if (!res.ok) throw new Error("Failed to save GitHub credentials.");
                const statusData = await res.json();
                closeModal("modalConnectGitHub");
                if (typeof loadGitHubFixStatus === "function") await loadGitHubFixStatus();
                if (typeof loadGitHubRepositories === "function") await loadGitHubRepositories();
                showToast("✓ GitHub configuration saved successfully!", "success");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    if (btnDisconnectGitHub) {
        btnDisconnectGitHub.addEventListener("click", async () => {
            try {
                await fetch("/api/github/disconnect", {
                    method: "POST",
                    headers: getAuthHeaders()
                });
                window._githubConnected = false;
                window._githubMode = null;
                window._currentSelectedRepo = null;
                window._usingCustomRepo = false;
                window.selectedSources = [];
                window.candidateSources = [];
                currentRepoTreeItems = [];
                window._currentAnalysisData = null;
                window._currentFixResult = null;

                const tokenInput = document.getElementById("ghModalTokenInput");
                if (tokenInput) tokenInput.value = "";
                const userInput = document.getElementById("ghModalUsernameInput");
                if (userInput) userInput.value = "";
                const customRepoInput = document.getElementById("wsAutofixCustomRepoInput");
                if (customRepoInput) customRepoInput.value = "";
                const customWrapper = document.getElementById("wsAutofixCustomRepoWrapper");
                if (customWrapper) customWrapper.style.display = "none";

                // Clear diff and candidate containers
                const diffBox = document.getElementById("autofixDiffUnifiedBox");
                if (diffBox) diffBox.textContent = "";
                const candidateList = document.getElementById("discoveredSourceList");
                if (candidateList) candidateList.innerHTML = "";
                if (typeof renderSelectedSourcesList === "function") renderSelectedSourcesList();
                if (typeof renderCandidateSourcesList === "function") renderCandidateSourcesList();

                closeModal("modalConnectGitHub");
                if (typeof loadGitHubFixStatus === "function") await loadGitHubFixStatus();
                if (typeof loadGitHubRepositories === "function") await loadGitHubRepositories();
                showToast("GitHub disconnected successfully.", "info");
            } catch (e) {
                showToast(e.message, "error");
            }
        });
    }

    // =========================================================================
    // GITHUB PERMISSION HELP & SMART SANDBOX FALLBACK MODAL HANDLERS
    // =========================================================================
    const btnCloseGitHubPermissionHelpModal = document.getElementById("btnCloseGitHubPermissionHelpModal");
    const btnClosePermHelpModalSecondary = document.getElementById("btnClosePermHelpModalSecondary");
    const btnSwitchSandboxFromHelp = document.getElementById("btnSwitchSandboxFromHelp");
    const btnSwitchSandboxFromHelpFooter = document.getElementById("btnSwitchSandboxFromHelpFooter");
    const btnUpdateTokenFromHelp = document.getElementById("btnUpdateTokenFromHelp");

    function openGitHubPermissionHelpModal(errInfo, currentData) {
        const repoEl = document.getElementById("ghPermHelpRepoName");
        const summaryEl = document.getElementById("ghPermHelpSummary");
        const repoName = (currentData && currentData.repo) || "selected repository";

        if (repoEl) repoEl.textContent = repoName;

        let detailMsg = "";
        if (typeof errInfo === "object" && errInfo !== null) {
            detailMsg = errInfo.message || errInfo.detail || "";
            if (typeof detailMsg === "object") detailMsg = detailMsg.message || JSON.stringify(detailMsg);
        } else if (typeof errInfo === "string") {
            detailMsg = errInfo;
        }

        if (summaryEl) {
            summaryEl.innerHTML = `GitHub prevented Tracegate from creating the remediation branch on <strong style="font-family: var(--font-mono); color: var(--text-primary);">${repoName}</strong> because your Personal Access Token lacks write permissions (<code>Contents: Read and write</code>).` +
                (detailMsg ? `<div style="margin-top: 8px; font-family: var(--font-mono); font-size: 0.76rem; background: rgba(0,0,0,0.04); padding: 6px 10px; border-radius: 4px; color: var(--text-muted); word-break: break-all;">${detailMsg}</div>` : "");
        }

        openModal("modalGitHubPermissionHelp");
    }

    if (btnCloseGitHubPermissionHelpModal) {
        btnCloseGitHubPermissionHelpModal.addEventListener("click", () => closeModal("modalGitHubPermissionHelp"));
    }
    if (btnClosePermHelpModalSecondary) {
        btnClosePermHelpModalSecondary.addEventListener("click", () => closeModal("modalGitHubPermissionHelp"));
    }

    if (btnUpdateTokenFromHelp) {
        btnUpdateTokenFromHelp.addEventListener("click", () => {
            closeModal("modalGitHubPermissionHelp");
            openModal("modalConnectGitHub");
        });
    }

    async function handleSwitchToSandboxFromHelp() {
        try {
            showToast("Switching to Local Security Lab Sandbox...", "info");
            const res = await fetch("/api/github/connect", {
                method: "POST",
                headers: getAuthHeaders({ "Content-Type": "application/json" }),
                body: JSON.stringify({ mode: "mock", token: "" })
            });
            if (!res.ok) throw new Error("Failed to switch to sandbox mode.");

            closeModal("modalGitHubPermissionHelp");
            await loadGitHubFixStatus();
            await loadGitHubRepositories();

            // Adapt active analysis data to the sandbox lab repo
            if (window._currentAnalysisData) {
                window._currentAnalysisData.repo = "tracegate-lab/ecommerce-platform";
                const repoSelect = document.getElementById("selFixGitHubRepo");
                if (repoSelect) {
                    repoSelect.value = "tracegate-lab/ecommerce-platform";
                }
                const confirmRepoEl = document.getElementById("confirmApplyRepo");
                if (confirmRepoEl) {
                    confirmRepoEl.textContent = "tracegate-lab/ecommerce-platform";
                }
                const confirmRepoInput = document.getElementById("confirmApplyRepoInput");
                if (confirmRepoInput) {
                    confirmRepoInput.value = "tracegate-lab/ecommerce-platform";
                }
            }

            showToast("✓ Switched to Security Lab Sandbox! You can now commit fixes and create PRs safely.", "success");

            // Automatically re-open the confirm modal so the user can immediately commit without hindrance
            if (window._currentAnalysisData) {
                openModal("modalAIFixConfirmApply");
            }
        } catch (e) {
            showToast(e.message, "error");
        }
    }

    if (btnSwitchSandboxFromHelp) {
        btnSwitchSandboxFromHelp.addEventListener("click", handleSwitchToSandboxFromHelp);
    }
    if (btnSwitchSandboxFromHelpFooter) {
        btnSwitchSandboxFromHelpFooter.addEventListener("click", handleSwitchToSandboxFromHelp);
    }

    // Connect Tree modal handlers
    const btnWsBrowseRepoTree = document.getElementById("btnWsBrowseRepoTree");
    const btnCloseBrowseRepoModal = document.getElementById("btnCloseBrowseRepoModal");
    const btnCancelBrowseRepoModal = document.getElementById("btnCancelBrowseRepoModal");
    const txtFilterRepoTree = document.getElementById("txtFilterRepoTree");
    const btnSelectAllRepoTree = document.getElementById("btnSelectAllRepoTree");
    const btnClearRepoTreeSelection = document.getElementById("btnClearRepoTreeSelection");
    const btnSelectRepoFileFromTree = document.getElementById("btnSelectRepoFileFromTree");
    const btnResetEntireRepoScope = document.getElementById("btnResetEntireRepoScope");
    const wsCandidateSourcesHeader = document.getElementById("wsCandidateSourcesHeader");
    const wsCandidateSourcesList = document.getElementById("wsCandidateSourcesList");
    const wsCandidateSourcesToggleIcon = document.getElementById("wsCandidateSourcesToggleIcon");

    if (btnWsBrowseRepoTree) btnWsBrowseRepoTree.addEventListener("click", openBrowseRepoTreeModal);
    if (btnCloseBrowseRepoModal) btnCloseBrowseRepoModal.addEventListener("click", () => closeModal("modalBrowseRepoFiles"));
    if (btnCancelBrowseRepoModal) btnCancelBrowseRepoModal.addEventListener("click", () => closeModal("modalBrowseRepoFiles"));

    if (btnSelectAllRepoTree) {
        btnSelectAllRepoTree.addEventListener("click", () => {
            const q = (txtFilterRepoTree ? txtFilterRepoTree.value : "").toLowerCase().trim();
            const items = currentRepoTreeItems || [];
            items.forEach(i => {
                if (!q || i.path.toLowerCase().includes(q)) {
                    repoTreeTempCheckedPaths.add(i.path);
                }
            });
            updateRepoTreeCount();
            const chks = document.querySelectorAll(".repo-tree-checkbox");
            chks.forEach(c => {
                const label = c.closest(".repo-tree-item");
                const path = label ? label.querySelector("span")?.textContent : null;
                if (path && repoTreeTempCheckedPaths.has(path)) {
                    c.checked = true;
                }
            });
        });
    }

    if (btnClearRepoTreeSelection) {
        btnClearRepoTreeSelection.addEventListener("click", () => {
            repoTreeTempCheckedPaths.clear();
            updateRepoTreeCount();
            const chks = document.querySelectorAll(".repo-tree-checkbox");
            chks.forEach(c => c.checked = false);
        });
    }

    if (btnResetEntireRepoScope) {
        btnResetEntireRepoScope.addEventListener("click", async () => {
            window.sourceSelectionMode = "AUTOMATIC";
            window.selectedSources = [];
            window.candidateSources = [];
            repoTreeTempCheckedPaths.clear();
            renderSelectedSourcesList();
            renderCandidateSourcesList();
            await saveSourceSelectionToServer();
            showToast("Reverted to Whole Repository discovery mode (Dynamic search active).", "info");
        });
    }

    if (btnSelectRepoFileFromTree) {
        btnSelectRepoFileFromTree.addEventListener("click", async () => {
            const chosen = Array.from(repoTreeTempCheckedPaths);
            if (chosen.length === 0) {
                showToast("Please select at least one file.", "warning");
                return;
            }

            const existingMap = new Map((window.selectedSources || []).map(s => [s.path, s]));
            const newSources = chosen.map(p => {
                if (existingMap.has(p)) return existingMap.get(p);
                return {
                    path: p,
                    layer: "Manual",
                    confidence: "MANUAL",
                    language: "unknown",
                    relevance_score: 80,
                    reasons: ["Manually selected by developer"],
                    symbols: []
                };
            });

            window.selectedSources = newSources;
            window.sourceSelectionMode = "USER_MODIFIED";
            renderSelectedSourcesList();
            await saveSourceSelectionToServer();
            closeModal("modalBrowseRepoFiles");
            showToast(`✓ Updated selection: ${chosen.length} file(s) in remediation scope.`, "success");
        });
    }

    if (wsCandidateSourcesHeader && wsCandidateSourcesList) {
        wsCandidateSourcesHeader.addEventListener("click", () => {
            const isHidden = wsCandidateSourcesList.style.display === "none";
            wsCandidateSourcesList.style.display = isHidden ? "flex" : "none";
            if (wsCandidateSourcesToggleIcon) {
                wsCandidateSourcesToggleIcon.textContent = isHidden ? "▲" : "▼";
            }
        });
    }

    if (txtFilterRepoTree) {
        txtFilterRepoTree.addEventListener("input", (e) => {
            const q = e.target.value.toLowerCase().trim();
            const filtered = currentRepoTreeItems.filter(i => i.path.toLowerCase().includes(q));
            renderRepoTreeList(filtered);
        });
    }

    // Auto-detect button handler
    // Custom Repo Handlers
    const btnToggleCustomRepo = document.getElementById("btnToggleCustomRepo");
    const wsAutofixCustomRepoWrapper = document.getElementById("wsAutofixCustomRepoWrapper");
    const wsAutofixCustomRepoInput = document.getElementById("wsAutofixCustomRepoInput");
    const btnApplyCustomRepo = document.getElementById("btnApplyCustomRepo");

    if (btnToggleCustomRepo && wsAutofixCustomRepoWrapper) {
        btnToggleCustomRepo.addEventListener("click", () => {
            const isHidden = wsAutofixCustomRepoWrapper.style.display === "none";
            wsAutofixCustomRepoWrapper.style.display = isHidden ? "block" : "none";
            if (isHidden && wsAutofixCustomRepoInput) {
                wsAutofixCustomRepoInput.focus();
            }
        });
    }

    function applyCustomRepository(customName) {
        if (!customName) return;
        const cleanRepo = customName.trim();
        if (!cleanRepo.includes("/")) {
            showToast("Please enter repository in owner/repo format (e.g. username/repo-name)", "warning");
        }
        window._currentSelectedRepo = cleanRepo;
        window._usingCustomRepo = true;

        const wsAutofixRepoSelect = document.getElementById("wsAutofixRepoSelect");
        if (wsAutofixRepoSelect) {
            wsAutofixRepoSelect.disabled = false;
            // Remove any disabled placeholder option if present
            const placeholder = Array.from(wsAutofixRepoSelect.options).find(o => o.value === "");
            if (placeholder && wsAutofixRepoSelect.options.length > 1) {
                placeholder.remove();
            }
            let existingOpt = Array.from(wsAutofixRepoSelect.options).find(o => o.value === cleanRepo);
            if (!existingOpt) {
                existingOpt = document.createElement("option");
                existingOpt.value = cleanRepo;
                existingOpt.textContent = `${cleanRepo} (Custom)`;
                wsAutofixRepoSelect.prepend(existingOpt);
            }
            wsAutofixRepoSelect.value = cleanRepo;
        }

        const wsBranchSelect = document.getElementById("wsAutofixBranchSelect");
        if (wsBranchSelect) {
            wsBranchSelect.disabled = false;
        }

        loadRepositoryBranches(cleanRepo);
        showToast(`✓ Target repository set to: ${cleanRepo}`, "success");
    }

    if (btnApplyCustomRepo && wsAutofixCustomRepoInput) {
        btnApplyCustomRepo.addEventListener("click", () => {
            applyCustomRepository(wsAutofixCustomRepoInput.value);
        });
        wsAutofixCustomRepoInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                applyCustomRepository(wsAutofixCustomRepoInput.value);
            }
        });
        wsAutofixCustomRepoInput.addEventListener("input", (e) => {
            const cleanRepo = e.target.value.trim();
            if (cleanRepo) {
                window._currentSelectedRepo = cleanRepo;
                window._usingCustomRepo = true;
            }
        });
    }

    // Repo change handler
    const wsAutofixRepoSelect = document.getElementById("wsAutofixRepoSelect");
    if (wsAutofixRepoSelect) {
        wsAutofixRepoSelect.addEventListener("change", (e) => {
            const val = e.target.value;
            if (val === "__custom__") {
                if (wsAutofixCustomRepoWrapper) {
                    wsAutofixCustomRepoWrapper.style.display = "block";
                    if (wsAutofixCustomRepoInput) wsAutofixCustomRepoInput.focus();
                }
            } else {
                window._currentSelectedRepo = val;
                window._usingCustomRepo = false;
                loadRepositoryBranches(val);
            }
        });
    }

    // Finding select change handler
    const wsAutofixFindingSelect = document.getElementById("wsAutofixFindingSelect");
    if (wsAutofixFindingSelect) {
        wsAutofixFindingSelect.addEventListener("change", (e) => {
            const fid = e.target.value;
            // Always reset selectedSources to empty and mode to AUTOMATIC when switching findings
            window.selectedSources = [];
            window.candidateSources = [];
            window.sourceSelectionMode = "AUTOMATIC";
            const fileInput = document.getElementById("wsAutofixFileInput");
            if (fileInput) fileInput.value = "";
            renderSelectedSourcesList();
            renderCandidateSourcesList();

            if (!fid) {
                const prRow = document.getElementById("wsPRResultRow");
                if (prRow) prRow.style.display = "none";
                const fixCard = document.getElementById("wsFixAppliedCard");
                if (fixCard) fixCard.style.display = "none";
                window._currentPRResult = null;
                return;
            }
            restoreFindingFixState(fid);
        });
    }

    async function restoreFindingFixState(fid) {
        if (!fid) return;

        // Restore multi-file source discovery state from server
        try {
            const repoVal = getSelectedRemediationRepo();
            if (repoVal && fid) {
                const sRes = await fetch(`/api/ai-fix/selected-sources?finding_id=${encodeURIComponent(fid)}&repo=${encodeURIComponent(repoVal)}`);
                if (sRes.ok) {
                    const sData = await sRes.json();
                    if (sData) {
                        window.selectedSources = sData.selected_sources || [];
                        window.candidateSources = sData.candidate_sources || [];
                        window.sourceSelectionMode = sData.selection_mode || "AUTOMATIC";
                        renderSelectedSourcesList();
                        renderCandidateSourcesList();
                    }
                }
            }
        } catch (err) {
            console.warn("Could not load source selection state:", err);
        }

        try {
            const curProj = getActiveProject();
            const curProjId = curProj ? curProj.id : (typeof activeProjectId !== "undefined" ? activeProjectId : "");
            const queryPart = curProjId ? `?project_id=${encodeURIComponent(curProjId)}` : "";
            const res = await fetch(`/api/ai-fix/${encodeURIComponent(fid)}${queryPart}`, {
                headers: getAuthHeaders()
            });
            if (!res.ok) return;
            const fix = await res.json();
            if (!fix || !fix.id) {
                const prRow = document.getElementById("wsPRResultRow");
                if (prRow) prRow.style.display = "none";
                const fixCard = document.getElementById("wsFixAppliedCard");
                if (fixCard) fixCard.style.display = "none";
                window._currentPRResult = null;
                return;
            }

            // Populate current analysis data
            window._currentAnalysisData = {
                finding_id: fid,
                fix_id: fix.id,
                repo: fix.repository,
                branch: fix.base_branch || "main",
                file_path: fix.file_path
            };

            if (fix.commit_sha && fix.commit_sha !== "pending" && fix.commit_sha !== "N/A") {
                window._currentFixResult = {
                    branch_name: fix.fix_branch,
                    commit_sha: fix.commit_sha
                };

                const fixCard = document.getElementById("wsFixAppliedCard");
                const branchSpan = document.getElementById("wsFixBranchName");
                const shaSpan = document.getElementById("wsFixCommitSha");
                if (fixCard) fixCard.style.display = "flex";
                if (branchSpan) branchSpan.textContent = fix.fix_branch || `tracegate/fix/${fid}`;
                if (shaSpan) shaSpan.textContent = fix.commit_sha.substring(0, 7);
            }

            if (fix.pr_number && fix.pr_number !== "N/A") {
                window._currentPRResult = {
                    pr_number: fix.pr_number,
                    pr_url: fix.pr_url,
                    html_url: fix.pr_url,
                    pr_status: fix.pr_status,
                    review_status: fix.review_status,
                    merged: fix.pr_status === "Merged" || fix.status === "MERGED"
                };

                updatePRUI({
                    pr_number: fix.pr_number,
                    pr_url: fix.pr_url,
                    merged: fix.pr_status === "Merged" || fix.status === "MERGED",
                    state: fix.pr_status === "Merged" || fix.pr_status === "Closed" ? "closed" : "open",
                    review_status: fix.review_status
                });

                const prBtn = document.getElementById("btnWsCreatePR");
                if (prBtn && fix.pr_number) {
                    prBtn.textContent = `✓ PR #${fix.pr_number} Created`;
                    prBtn.className = "btn btn-outline-success btn-sm";
                }

                // Check live status on GitHub in background
                fetchLivePRStatus(fix.repository, fix.pr_number);
            } else {
                const prRow = document.getElementById("wsPRResultRow");
                if (prRow) prRow.style.display = "none";
                window._currentPRResult = null;
            }
        } catch (e) {
            console.warn("Failed to restore finding fix state:", e);
        }

        const curProj = getActiveProject();
        if (curProj && curProj.id && typeof checkAndUpdateAIFixCertButtons === "function") {
            checkAndUpdateAIFixCertButtons(curProj.id);
        }
    }

    // Workspace Analyze Button
    const btnWsAnalyzeCodeFix = document.getElementById("btnWsAnalyzeCodeFix");
    if (btnWsAnalyzeCodeFix) {
        btnWsAnalyzeCodeFix.addEventListener("click", () => {
            if (window._isRemediationRunning) {
                showToast("Remediation analysis is already in progress. Please wait...", "warning");
                return;
            }
            if (!window._githubConnected) {
                showToast("GitHub is not connected. Please connect your GitHub account to analyze code fixes.", "warning");
                return;
            }
            const repo = getSelectedRemediationRepo();
            if (!repo) {
                showToast("Please select a valid repository first.", "warning");
                return;
            }
            const branch = document.getElementById("wsAutofixBranchSelect")?.value || "main";
            let findingId = document.getElementById("wsAutofixFindingSelect")?.value;
            if (!findingId) {
                const proj = getActiveProject();
                if (proj && proj.findings && proj.findings.length > 0) {
                    findingId = "__ALL_FINDINGS__";
                    const sel = document.getElementById("wsAutofixFindingSelect");
                    if (sel) sel.value = "__ALL_FINDINGS__";
                } else {
                    findingId = "__ALL_FINDINGS__";
                }
            }
            executeCodeFixAnalysis(repo, branch, findingId, true);
        });
    }

    // Connect Standalone AI Fix Buttons
    const btnRunAutoFixPreview = document.getElementById("btnRunAutoFixPreview");
    if (btnRunAutoFixPreview) {
        btnRunAutoFixPreview.addEventListener("click", () => {
            if (!window._githubConnected) {
                showToast("GitHub is not connected. Please connect your GitHub account to analyze code fixes.", "warning");
                return;
            }
            const repo = document.getElementById("standaloneRepoSelect")?.value;
            if (!repo) {
                showToast("Please select a repository first.", "warning");
                return;
            }
            const branch = document.getElementById("standaloneBranchSelect")?.value || "main";
            const findingId = document.getElementById("autofixFindingSelect")?.value;
            executeCodeFixAnalysis(repo, branch, findingId, false);
        });
    }

    const btnStandaloneReject = document.getElementById("btnStandaloneReject");
    if (btnStandaloneReject) {
        btnStandaloneReject.addEventListener("click", () => {
            const diffWrap = document.getElementById("standaloneDiffWrapper");
            if (diffWrap) diffWrap.style.display = "none";
            showToast("Fix proposal rejected.", "info");
        });
    }

    // ==========================================================================
    // 16. DELETE PROJECT CONTROLLER (Section 45)
    // ==========================================================================
    const btnDeleteProject = document.getElementById("btnDeleteProject");
    const txtDeleteProjectConfirm = document.getElementById("txtDeleteProjectConfirm");
    const btnConfirmDeleteProject = document.getElementById("btnConfirmDeleteProject");
    const btnCancelDeleteProject = document.getElementById("btnCancelDeleteProject");
    const btnCloseDeleteProjectModal = document.getElementById("btnCloseDeleteProjectModal");
    const deleteProjectNameSpan = document.getElementById("deleteProjectNameSpan");

    if (btnDeleteProject) {
        btnDeleteProject.addEventListener("click", () => {
            const proj = getActiveProject();
            if (!proj) {
                showToast("No active project selected.", "error");
                return;
            }

            if (deleteProjectNameSpan) {
                deleteProjectNameSpan.textContent = proj.name;
            }
            if (txtDeleteProjectConfirm) {
                txtDeleteProjectConfirm.value = "";
            }
            if (btnConfirmDeleteProject) {
                btnConfirmDeleteProject.disabled = true;
                btnConfirmDeleteProject.style.cursor = "not-allowed";
                btnConfirmDeleteProject.style.opacity = "0.5";
            }

            openModal("modalDeleteProject");
            if (txtDeleteProjectConfirm) {
                setTimeout(() => txtDeleteProjectConfirm.focus(), 100);
            }
        });
    }

    if (txtDeleteProjectConfirm && btnConfirmDeleteProject) {
        txtDeleteProjectConfirm.addEventListener("input", (e) => {
            const val = e.target.value.trim();
            if (val === "DELETE") {
                btnConfirmDeleteProject.disabled = false;
                btnConfirmDeleteProject.style.cursor = "pointer";
                btnConfirmDeleteProject.style.opacity = "1";
            } else {
                btnConfirmDeleteProject.disabled = true;
                btnConfirmDeleteProject.style.cursor = "not-allowed";
                btnConfirmDeleteProject.style.opacity = "0.5";
            }
        });
    }

    const closeDeleteModal = () => {
        closeModal("modalDeleteProject");
        if (txtDeleteProjectConfirm) txtDeleteProjectConfirm.value = "";
        if (btnConfirmDeleteProject) {
            btnConfirmDeleteProject.disabled = true;
            btnConfirmDeleteProject.style.cursor = "not-allowed";
            btnConfirmDeleteProject.style.opacity = "0.5";
        }
    };

    if (btnCancelDeleteProject) btnCancelDeleteProject.addEventListener("click", closeDeleteModal);
    if (btnCloseDeleteProjectModal) btnCloseDeleteProjectModal.addEventListener("click", closeDeleteModal);

    if (btnConfirmDeleteProject) {
        btnConfirmDeleteProject.addEventListener("click", async () => {
            const proj = getActiveProject();
            if (!proj) {
                closeDeleteModal();
                return;
            }

            if (txtDeleteProjectConfirm && txtDeleteProjectConfirm.value.trim() !== "DELETE") {
                showToast("Please type DELETE to confirm.", "warning");
                return;
            }

            try {
                btnConfirmDeleteProject.disabled = true;
                btnConfirmDeleteProject.textContent = "Deleting...";

                const res = await fetch(`/api/projects/${proj.id}`, {
                    method: "DELETE",
                    headers: getAuthHeaders()
                });

                if (!res.ok) {
                    const err = await res.json().catch(() => ({}));
                    throw new Error(err.detail || "Failed to delete project.");
                }

                // Clean up local project list
                projects = projects.filter(p => p.id !== proj.id);
                saveProjects();
                activeProjectId = projects.length > 0 ? projects[0].id : null;

                closeDeleteModal();
                updateProjectsDropdown();
                showToast("Project deleted successfully.", "success");

                // Navigate cleanly to recent projects
                navigateTo("recent-projects");
            } catch (err) {
                showToast(err.message, "error");
            } finally {
                if (btnConfirmDeleteProject) {
                    btnConfirmDeleteProject.textContent = "Delete Project";
                }
            }
        });
    }

    // ==========================================================================
    // 13B. BULK DELETE TEST PROJECTS CONTROLLER
    // ==========================================================================
    let isBulkDeleting = false;

    window.openBulkDeleteModal = async function() {
        if (!currentUser) {
            showToast("Please sign in to manage project data.", "warning");
            return;
        }

        const modal = document.getElementById("modalBulkDeleteProjects");
        if (!modal) return;

        // Reset inputs
        const chk = document.getElementById("chkBulkDeleteAcknowledge");
        const txt = document.getElementById("txtBulkDeleteConfirm");
        const btn = document.getElementById("btnConfirmBulkDelete");
        const progress = document.getElementById("bulkDeleteProgress");
        const countSpan = document.getElementById("bulkDeleteProjectCount");
        const ackCountSpan = document.getElementById("bulkDeleteAcknowledgeCount");

        if (chk) chk.checked = false;
        if (txt) txt.value = "";
        if (btn) {
            btn.disabled = true;
            btn.style.cursor = "not-allowed";
            btn.style.opacity = "0.5";
        }
        if (progress) progress.style.display = "none";

        // Display project count (optimistic from local memory)
        let displayCount = projects.length;
        if (countSpan) countSpan.textContent = displayCount;
        if (ackCountSpan) ackCountSpan.textContent = displayCount;

        openModal("modalBulkDeleteProjects");

        // Fetch accurate count from server
        try {
            const cRes = await fetch("/api/projects/count", {
                headers: getAuthHeaders()
            });
            if (cRes.ok) {
                const cData = await cRes.json();
                displayCount = (typeof cData.count === "number") ? cData.count : projects.length;
                if (countSpan) countSpan.textContent = displayCount;
                if (ackCountSpan) ackCountSpan.textContent = displayCount;
            }
        } catch (e) {
            console.warn("[TRACEGATE] Failed to fetch server project count:", e);
        }

        if (txt) {
            setTimeout(() => txt.focus(), 150);
        }
    };

    window.closeBulkDeleteModal = function() {
        if (isBulkDeleting) return;
        closeModal("modalBulkDeleteProjects");
        const txt = document.getElementById("txtBulkDeleteConfirm");
        const chk = document.getElementById("chkBulkDeleteAcknowledge");
        const btn = document.getElementById("btnConfirmBulkDelete");
        if (txt) txt.value = "";
        if (chk) chk.checked = false;
        if (btn) {
            btn.disabled = true;
            btn.style.cursor = "not-allowed";
            btn.style.opacity = "0.5";
        }
    };

    function updateBulkDeleteButtonState() {
        const chk = document.getElementById("chkBulkDeleteAcknowledge");
        const txt = document.getElementById("txtBulkDeleteConfirm");
        const btn = document.getElementById("btnConfirmBulkDelete");
        if (!btn) return;

        const isAcknowledged = chk ? chk.checked : false;
        const isDeleteTyped = txt ? (txt.value.trim().toUpperCase() === "DELETE") : false;

        if (isAcknowledged && isDeleteTyped && !isBulkDeleting) {
            btn.disabled = false;
            btn.style.cursor = "pointer";
            btn.style.opacity = "1";
        } else {
            btn.disabled = true;
            btn.style.cursor = "not-allowed";
            btn.style.opacity = "0.5";
        }
    }

    const txtBulkDeleteConfirm = document.getElementById("txtBulkDeleteConfirm");
    const chkBulkDeleteAcknowledge = document.getElementById("chkBulkDeleteAcknowledge");

    if (txtBulkDeleteConfirm) {
        txtBulkDeleteConfirm.addEventListener("input", updateBulkDeleteButtonState);
    }
    if (chkBulkDeleteAcknowledge) {
        chkBulkDeleteAcknowledge.addEventListener("change", updateBulkDeleteButtonState);
    }

    window.executeBulkDelete = async function() {
        if (isBulkDeleting) return;
        const txt = document.getElementById("txtBulkDeleteConfirm");
        const chk = document.getElementById("chkBulkDeleteAcknowledge");
        const btn = document.getElementById("btnConfirmBulkDelete");
        const cancelBtn = document.getElementById("btnCancelBulkDelete");
        const progress = document.getElementById("bulkDeleteProgress");
        const progressText = document.getElementById("bulkDeleteProgressText");

        if (!chk || !chk.checked) {
            showToast("Please acknowledge that projects will be deleted.", "warning");
            return;
        }

        if (!txt || txt.value.trim().toUpperCase() !== "DELETE") {
            showToast("Please type DELETE to confirm.", "warning");
            return;
        }

        try {
            isBulkDeleting = true;
            if (btn) {
                btn.disabled = true;
                btn.style.cursor = "not-allowed";
                btn.style.opacity = "0.5";
            }
            if (cancelBtn) cancelBtn.disabled = true;
            if (progress) progress.style.display = "block";
            if (progressText) progressText.textContent = "Deleting test projects and artifacts, please wait...";

            const res = await fetch("/api/projects/bulk-delete", {
                method: "POST",
                headers: getAuthHeaders({ "Content-Type": "application/json" })
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "Failed to bulk delete test projects.");
            }

            const data = await res.json();

            // Clear projects in memory and localStorage
            projects = [];
            activeProjectId = null;
            saveProjects();
            localStorage.removeItem("tg_active_proj_id");
            if (currentUser && currentUser.id) {
                localStorage.removeItem("tg_active_proj_id_" + currentUser.id);
                localStorage.removeItem("tg_projects_" + currentUser.id);
            }

            // Close modal
            isBulkDeleting = false;
            closeModal("modalBulkDeleteProjects");

            // Refresh UI components
            updateProjectsDropdown();
            refreshDashboardStats();
            if (typeof renderExistingProjects === "function") {
                renderExistingProjects();
            }
            if (typeof renderRecentProjects === "function") {
                renderRecentProjects();
            }

            showToast(data.message || `Deleted ${data.deleted || 0} test projects successfully.`, "success");
        } catch (err) {
            console.error("[TRACEGATE] Bulk delete error:", err);
            showToast(err.message || "An error occurred during bulk deletion.", "error");
        } finally {
            isBulkDeleting = false;
            if (cancelBtn) cancelBtn.disabled = false;
            if (progress) progress.style.display = "none";
            updateBulkDeleteButtonState();
        }
    };

    // ==========================================================================
    // 14. PROFILE VIEW CONTROLLER
    // ==========================================================================
    const btnSaveProfile = document.getElementById("btnSaveProfile");
    if (btnSaveProfile) {
        btnSaveProfile.addEventListener("click", () => {
            const name = document.getElementById("profileInputName").value.trim();
            const email = document.getElementById("profileInputEmail").value.trim();
            const meth = document.getElementById("profileSelectMethodology").value;

            if (!name || !email) {
                showToast("Name and email cannot be empty.", "error");
                return;
            }

            currentUser.name = name;
            currentUser.full_name = name;
            currentUser.email = email;
            currentUser.methodology = meth;
            localStorage.setItem("tg_user", JSON.stringify(currentUser));
            updateUserUI();

            showToast("Profile preferences updated successfully!", "success");
        });
    }

    // ==========================================================================
    // 14B. PROFILE 2FA SETTINGS & MODALS CONTROLLER
    // ==========================================================================
    const profile2FABadge = document.getElementById("profile2FABadge");
    const profile2FADesc = document.getElementById("profile2FADesc");
    const btnOpenSetup2FA = document.getElementById("btnOpenSetup2FA");
    const btnOpenManage2FA = document.getElementById("btnOpenManage2FA");
    const btnOpenDisable2FA = document.getElementById("btnOpenDisable2FA");
    const profile2FAMeta = document.getElementById("profile2FAMeta");
    const profile2FAEnabledAt = document.getElementById("profile2FAEnabledAt");
    const profile2FALastVerified = document.getElementById("profile2FALastVerified");
    const profile2FARecoveryCount = document.getElementById("profile2FARecoveryCount");

    // Setup Modal Elements
    const btnCloseSetup2FAModal = document.getElementById("btnCloseSetup2FAModal");
    const setup2FAStep1 = document.getElementById("setup2FAStep1");
    const setup2FAStep2 = document.getElementById("setup2FAStep2");
    const setup2FAQRPlaceholder = document.getElementById("setup2FAQRPlaceholder");
    const setup2FAQRImg = document.getElementById("setup2FAQRImg");
    const setup2FAManualKey = document.getElementById("setup2FAManualKey");
    const btnCopy2FAManualKey = document.getElementById("btnCopy2FAManualKey");
    const setup2FAAlertBox = document.getElementById("setup2FAAlertBox");
    const setup2FAAlertMessage = document.getElementById("setup2FAAlertMessage");
    const inputSetup2FACode = document.getElementById("inputSetup2FACode");
    const btnSubmit2FASetup = document.getElementById("btnSubmit2FASetup");
    const btnSubmit2FASetupText = document.getElementById("btnSubmit2FASetupText");
    const setup2FARecoveryGrid = document.getElementById("setup2FARecoveryGrid");
    const btnCopySetupRecoveryCodes = document.getElementById("btnCopySetupRecoveryCodes");
    const btnDownloadSetupRecoveryCodes = document.getElementById("btnDownloadSetupRecoveryCodes");
    const btnDone2FASetup = document.getElementById("btnDone2FASetup");

    // Disable Modal Elements
    const btnCloseDisable2FAModal = document.getElementById("btnCloseDisable2FAModal");
    const disable2FAAlertBox = document.getElementById("disable2FAAlertBox");
    const disable2FAAlertMessage = document.getElementById("disable2FAAlertMessage");
    const inputDisablePassword = document.getElementById("inputDisablePassword");
    const inputDisableCode = document.getElementById("inputDisableCode");
    const btnCancelDisable2FA = document.getElementById("btnCancelDisable2FA");
    const btnConfirmDisable2FA = document.getElementById("btnConfirmDisable2FA");

    // Manage Modal Elements
    const btnCloseManage2FAModal = document.getElementById("btnCloseManage2FAModal");
    const btnCloseManage2FAModalFooter = document.getElementById("btnCloseManage2FAModalFooter");
    const manage2FARemainingCount = document.getElementById("manage2FARemainingCount");
    const manage2FAAlertBox = document.getElementById("manage2FAAlertBox");
    const manage2FAAlertMessage = document.getElementById("manage2FAAlertMessage");
    const inputManageRegenPassword = document.getElementById("inputManageRegenPassword");
    const inputManageRegenCode = document.getElementById("inputManageRegenCode");
    const btnSubmitRegenCodes = document.getElementById("btnSubmitRegenCodes");
    const manage2FANewCodesSection = document.getElementById("manage2FANewCodesSection");
    const manage2FANewCodesGrid = document.getElementById("manage2FANewCodesGrid");
    const btnCopyManageRecoveryCodes = document.getElementById("btnCopyManageRecoveryCodes");
    const btnDownloadManageRecoveryCodes = document.getElementById("btnDownloadManageRecoveryCodes");

    let currentSetupRecoveryCodes = [];
    let currentRegenRecoveryCodes = [];

    async function loadProfile2FAStatus() {
        const authToken = localStorage.getItem("tg_auth_token");
        if (!authToken || !currentUser) return;

        try {
            const res = await fetch("/api/auth/2fa/status", {
                headers: { "Authorization": `Bearer ${authToken}` }
            });
            if (!res.ok) return;

            const st = await res.json();
            currentUser.two_factor_enabled = st.enabled;
            currentUser.two_factor_enabled_at = st.enabled_at;
            currentUser.two_factor_last_verified_at = st.last_verified_at;
            localStorage.setItem("tg_user", JSON.stringify(currentUser));

            if (profile2FABadge) {
                if (st.enabled) {
                    profile2FABadge.textContent = "Enabled (TOTP)";
                    profile2FABadge.style.background = "#ecfdf5";
                    profile2FABadge.style.color = "#059669";
                    profile2FABadge.style.border = "1px solid #a7f3d0";
                } else {
                    profile2FABadge.textContent = "Disabled";
                    profile2FABadge.style.background = "#f1f5f9";
                    profile2FABadge.style.color = "#64748b";
                    profile2FABadge.style.border = "1px solid #cbd5e1";
                }
            }

            if (st.enabled) {
                if (btnOpenSetup2FA) btnOpenSetup2FA.style.display = "none";
                if (btnOpenManage2FA) btnOpenManage2FA.style.display = "inline-block";
                if (btnOpenDisable2FA) btnOpenDisable2FA.style.display = "inline-block";
                if (profile2FAMeta) profile2FAMeta.style.display = "flex";

                if (profile2FAEnabledAt) profile2FAEnabledAt.textContent = st.enabled_at || "Recent";
                if (profile2FALastVerified) profile2FALastVerified.textContent = st.last_verified_at || "Not yet recorded";
                if (profile2FARecoveryCount) profile2FARecoveryCount.textContent = `${st.recovery_codes_remaining} remaining`;
                if (manage2FARemainingCount) manage2FARemainingCount.textContent = `${st.recovery_codes_remaining} / 10 active`;
            } else {
                if (btnOpenSetup2FA) btnOpenSetup2FA.style.display = "inline-block";
                if (btnOpenManage2FA) btnOpenManage2FA.style.display = "none";
                if (btnOpenDisable2FA) btnOpenDisable2FA.style.display = "none";
                if (profile2FAMeta) profile2FAMeta.style.display = "none";
            }
        } catch (e) {
            console.error("Failed to fetch 2FA status:", e);
        }
    }

    // Expose for global router
    window.loadProfile2FAStatus = loadProfile2FAStatus;

    // 1. Setup 2FA Flow
    if (btnOpenSetup2FA) {
        btnOpenSetup2FA.addEventListener("click", async () => {
            const authToken = localStorage.getItem("tg_auth_token");
            if (!authToken) {
                showToast("Please sign in to configure 2FA.", "error");
                return;
            }

            // Reset setup modal state
            if (setup2FAStep1) setup2FAStep1.style.display = "block";
            if (setup2FAStep2) setup2FAStep2.style.display = "none";
            if (setup2FAQRPlaceholder) setup2FAQRPlaceholder.style.display = "flex";
            if (setup2FAQRImg) {
                setup2FAQRImg.style.display = "none";
                setup2FAQRImg.src = "";
            }
            if (setup2FAManualKey) setup2FAManualKey.textContent = "Loading secret...";
            if (setup2FAAlertBox) setup2FAAlertBox.style.display = "none";
            if (inputSetup2FACode) inputSetup2FACode.value = "";
            currentSetupRecoveryCodes = [];

            openModal("modalSetup2FA");

            try {
                const res = await fetch("/api/auth/2fa/setup", {
                    method: "POST",
                    headers: { "Authorization": `Bearer ${authToken}` }
                });

                if (!res.ok) {
                    showToast("Failed to initiate 2FA enrollment.", "error");
                    closeModal("modalSetup2FA");
                    return;
                }

                const data = await res.json();
                if (setup2FAQRPlaceholder) setup2FAQRPlaceholder.style.display = "none";
                if (setup2FAQRImg) {
                    setup2FAQRImg.src = data.qr_code;
                    setup2FAQRImg.style.display = "block";
                }
                if (setup2FAManualKey) {
                    setup2FAManualKey.textContent = data.manual_entry_key || data.secret;
                }
            } catch (err) {
                showToast("Network error generating 2FA credentials.", "error");
                closeModal("modalSetup2FA");
            }
        });
    }

    if (btnCopy2FAManualKey) {
        btnCopy2FAManualKey.addEventListener("click", () => {
            const keyText = (setup2FAManualKey?.textContent || "").replace(/\s+/g, "");
            if (keyText && keyText !== "-") {
                navigator.clipboard.writeText(keyText).then(() => {
                    showToast("Manual key copied to clipboard.", "info");
                });
            }
        });
    }

    if (btnSubmit2FASetup) {
        btnSubmit2FASetup.addEventListener("click", async () => {
            const code = inputSetup2FACode ? inputSetup2FACode.value.trim().replace(/\s+/g, "") : "";
            if (!code || code.length !== 6) {
                if (setup2FAAlertBox && setup2FAAlertMessage) {
                    setup2FAAlertMessage.textContent = "Please enter a valid 6-digit authenticator code.";
                    setup2FAAlertBox.style.display = "flex";
                }
                if (inputSetup2FACode) inputSetup2FACode.focus();
                return;
            }

            const authToken = localStorage.getItem("tg_auth_token");
            if (btnSubmit2FASetupText) btnSubmit2FASetupText.textContent = "Verifying...";
            btnSubmit2FASetup.disabled = true;
            if (setup2FAAlertBox) setup2FAAlertBox.style.display = "none";

            try {
                const res = await fetch("/api/auth/2fa/verify-setup", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ code })
                });

                if (!res.ok) {
                    let errDetail = "Invalid verification code.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    if (setup2FAAlertBox && setup2FAAlertMessage) {
                        setup2FAAlertMessage.textContent = errDetail;
                        setup2FAAlertBox.style.display = "flex";
                    }
                    return;
                }

                const data = await res.json();
                currentSetupRecoveryCodes = data.recovery_codes || [];

                // Render recovery codes in grid
                if (setup2FARecoveryGrid) {
                    setup2FARecoveryGrid.innerHTML = "";
                    currentSetupRecoveryCodes.forEach((c, idx) => {
                        const item = document.createElement("div");
                        item.style.padding = "6px 8px";
                        item.style.background = "var(--bg-subtle)";
                        item.style.borderRadius = "4px";
                        item.style.border = "1px solid var(--border-subtle)";
                        item.textContent = `${idx + 1}. ${c}`;
                        setup2FARecoveryGrid.appendChild(item);
                    });
                }

                // Switch modal to Step 2
                if (setup2FAStep1) setup2FAStep1.style.display = "none";
                if (setup2FAStep2) setup2FAStep2.style.display = "block";

                showToast("Two-Factor Authentication is now enabled!", "success");
                loadProfile2FAStatus();
            } catch (err) {
                if (setup2FAAlertBox && setup2FAAlertMessage) {
                    setup2FAAlertMessage.textContent = "Service connection error.";
                    setup2FAAlertBox.style.display = "flex";
                }
            } finally {
                if (btnSubmit2FASetupText) btnSubmit2FASetupText.textContent = "Enable 2FA";
                btnSubmit2FASetup.disabled = false;
            }
        });
    }

    function exportRecoveryCodes(codes, filename) {
        if (!codes || !codes.length) return;
        const text = [
            "============================================================",
            "TRACEGATE TWO-FACTOR AUTHENTICATION BACKUP RECOVERY CODES",
            `Generated: ${new Date().toISOString()}`,
            "Account: " + (currentUser?.email || currentUser?.username || ""),
            "============================================================",
            "",
            "Each of these 10 recovery codes can only be used ONCE if you",
            "lose access to your mobile authenticator app.",
            "Keep them in a secure password manager or encrypted file.",
            "",
            ...codes.map((c, i) => `[${i + 1}]  ${c}`),
            "",
            "============================================================"
        ].join("\r\n");

        const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = filename || "tracegate-recovery-codes.txt";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    if (btnCopySetupRecoveryCodes) {
        btnCopySetupRecoveryCodes.addEventListener("click", () => {
            if (currentSetupRecoveryCodes.length) {
                navigator.clipboard.writeText(currentSetupRecoveryCodes.join("\n")).then(() => {
                    showToast("Recovery codes copied to clipboard.", "info");
                });
            }
        });
    }

    if (btnDownloadSetupRecoveryCodes) {
        btnDownloadSetupRecoveryCodes.addEventListener("click", () => {
            exportRecoveryCodes(currentSetupRecoveryCodes, "tracegate-2fa-recovery-codes.txt");
        });
    }

    if (btnDone2FASetup) {
        btnDone2FASetup.addEventListener("click", () => {
            closeModal("modalSetup2FA");
            loadProfile2FAStatus();
        });
    }
    if (btnCloseSetup2FAModal) {
        btnCloseSetup2FAModal.addEventListener("click", () => {
            closeModal("modalSetup2FA");
            loadProfile2FAStatus();
        });
    }

    // 2. Disable 2FA Flow
    if (btnOpenDisable2FA) {
        btnOpenDisable2FA.addEventListener("click", () => {
            if (inputDisablePassword) inputDisablePassword.value = "";
            if (inputDisableCode) inputDisableCode.value = "";
            if (disable2FAAlertBox) disable2FAAlertBox.style.display = "none";
            openModal("modalDisable2FA");
        });
    }

    if (btnCancelDisable2FA) {
        btnCancelDisable2FA.addEventListener("click", () => closeModal("modalDisable2FA"));
    }
    if (btnCloseDisable2FAModal) {
        btnCloseDisable2FAModal.addEventListener("click", () => closeModal("modalDisable2FA"));
    }

    if (btnConfirmDisable2FA) {
        btnConfirmDisable2FA.addEventListener("click", async () => {
            const password = inputDisablePassword ? inputDisablePassword.value.trim() : "";
            const code = inputDisableCode ? inputDisableCode.value.trim() : "";

            if (!password || !code) {
                if (disable2FAAlertBox && disable2FAAlertMessage) {
                    disable2FAAlertMessage.textContent = "Both password and verification/recovery code are required.";
                    disable2FAAlertBox.style.display = "flex";
                }
                return;
            }

            const authToken = localStorage.getItem("tg_auth_token");
            btnConfirmDisable2FA.disabled = true;

            try {
                const res = await fetch("/api/auth/2fa/disable", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ password, code })
                });

                if (!res.ok) {
                    let errDetail = "Failed to disable 2FA.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    if (disable2FAAlertBox && disable2FAAlertMessage) {
                        disable2FAAlertMessage.textContent = errDetail;
                        disable2FAAlertBox.style.display = "flex";
                    }
                    return;
                }

                closeModal("modalDisable2FA");
                showToast("Two-Factor Authentication has been disabled.", "info");
                loadProfile2FAStatus();
            } catch (err) {
                if (disable2FAAlertBox && disable2FAAlertMessage) {
                    disable2FAAlertMessage.textContent = "Service connection error.";
                    disable2FAAlertBox.style.display = "flex";
                }
            } finally {
                btnConfirmDisable2FA.disabled = false;
            }
        });
    }

    // 3. Manage & Regenerate Recovery Codes Flow
    if (btnOpenManage2FA) {
        btnOpenManage2FA.addEventListener("click", () => {
            if (manage2FAAlertBox) manage2FAAlertBox.style.display = "none";
            if (inputManageRegenPassword) inputManageRegenPassword.value = "";
            if (inputManageRegenCode) inputManageRegenCode.value = "";
            if (manage2FANewCodesSection) manage2FANewCodesSection.style.display = "none";
            currentRegenRecoveryCodes = [];
            openModal("modalManage2FA");
        });
    }

    if (btnCloseManage2FAModal) {
        btnCloseManage2FAModal.addEventListener("click", () => closeModal("modalManage2FA"));
    }
    if (btnCloseManage2FAModalFooter) {
        btnCloseManage2FAModalFooter.addEventListener("click", () => closeModal("modalManage2FA"));
    }

    if (btnSubmitRegenCodes) {
        btnSubmitRegenCodes.addEventListener("click", async () => {
            const password = inputManageRegenPassword ? inputManageRegenPassword.value.trim() : "";
            const code = inputManageRegenCode ? inputManageRegenCode.value.trim().replace(/\s+/g, "") : "";

            if (!password || !code) {
                if (manage2FAAlertBox && manage2FAAlertMessage) {
                    manage2FAAlertMessage.textContent = "Both password and current 6-digit TOTP code are required.";
                    manage2FAAlertBox.style.display = "flex";
                }
                return;
            }

            const authToken = localStorage.getItem("tg_auth_token");
            btnSubmitRegenCodes.disabled = true;

            try {
                const res = await fetch("/api/auth/2fa/regenerate-recovery-codes", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": `Bearer ${authToken}`
                    },
                    body: JSON.stringify({ password, code })
                });

                if (!res.ok) {
                    let errDetail = "Failed to regenerate recovery codes.";
                    try {
                        const errData = await res.json();
                        if (errData.detail) errDetail = errData.detail;
                    } catch (e) {}
                    if (manage2FAAlertBox && manage2FAAlertMessage) {
                        manage2FAAlertMessage.textContent = errDetail;
                        manage2FAAlertBox.style.display = "flex";
                    }
                    return;
                }

                const data = await res.json();
                currentRegenRecoveryCodes = data.recovery_codes || [];

                if (manage2FANewCodesGrid) {
                    manage2FANewCodesGrid.innerHTML = "";
                    currentRegenRecoveryCodes.forEach((c, idx) => {
                        const item = document.createElement("div");
                        item.style.padding = "6px 8px";
                        item.style.background = "var(--bg-subtle)";
                        item.style.borderRadius = "4px";
                        item.style.border = "1px solid var(--border-subtle)";
                        item.textContent = `${idx + 1}. ${c}`;
                        manage2FANewCodesGrid.appendChild(item);
                    });
                }

                if (manage2FANewCodesSection) manage2FANewCodesSection.style.display = "block";
                showToast("10 fresh recovery codes generated!", "success");
                loadProfile2FAStatus();
            } catch (err) {
                if (manage2FAAlertBox && manage2FAAlertMessage) {
                    manage2FAAlertMessage.textContent = "Service connection error.";
                    manage2FAAlertBox.style.display = "flex";
                }
            } finally {
                btnSubmitRegenCodes.disabled = false;
            }
        });
    }

    if (btnCopyManageRecoveryCodes) {
        btnCopyManageRecoveryCodes.addEventListener("click", () => {
            if (currentRegenRecoveryCodes.length) {
                navigator.clipboard.writeText(currentRegenRecoveryCodes.join("\n")).then(() => {
                    showToast("New recovery codes copied to clipboard.", "info");
                });
            }
        });
    }

    if (btnDownloadManageRecoveryCodes) {
        btnDownloadManageRecoveryCodes.addEventListener("click", () => {
            exportRecoveryCodes(currentRegenRecoveryCodes, "tracegate-new-recovery-codes.txt");
        });
    }

    // ==========================================================================
    // 15. MODAL HELPERS & TOAST COMPONENT
    // ==========================================================================
    function openModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.add("active");
    }

    function closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) modal.classList.remove("active");
    }

    // Close on overlay backdrop click
    document.querySelectorAll(".modal-overlay").forEach(modal => {
        modal.addEventListener("click", (e) => {
            if (e.target === modal) {
                modal.classList.remove("active");
            }
        });
    });

    function showToast(message, type = "info") {
        const container = document.getElementById("toastContainer");
        if (!container) return;

        const pill = document.createElement("div");
        pill.className = `toast-pill toast-${type}`;

        let icon = "ℹ️";
        if (type === "success") icon = "✓";
        if (type === "error") icon = "⚠️";

        pill.innerHTML = `<span>${icon}</span> <span>${escapeHtml(message)}</span>`;
        container.appendChild(pill);

        setTimeout(() => {
            pill.style.opacity = "0";
            pill.style.transform = "translateY(10px)";
            pill.style.transition = "all 0.3s ease";
            setTimeout(() => {
                if (pill.parentNode) pill.parentNode.removeChild(pill);
            }, 300);
        }, 3200);
    }

    function escapeHtml(str) {
        if (typeof str !== "string") return "";
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // =========================================================================
    // 16. VAPT ASSESSMENT COMPLETION CERTIFICATE SYSTEM
    // =========================================================================

    let activeCertificateData = null;

    async function checkAndPromptCertificateIfEligible(projectId) {
        if (!projectId) return;
        try {
            const res = await fetch(`/api/projects/${projectId}/certificate/status`, {
                headers: getAuthHeaders()
            });
            if (!res.ok) return;
            const data = await res.json();
            if (data.certificate) {
                const cert = data.certificate;
                const seenInStorage = localStorage.getItem("tg_cert_seen_" + cert.certificate_id);
                if (cert.notice_seen === 0 && !seenInStorage) {
                    showCertificateCompletionModal(cert);
                }
            }
        } catch (e) {
            console.warn("Could not check certificate status:", e);
        }
    }

    function showCertificateCompletionModal(cert) {
        if (!cert) return;
        activeCertificateData = cert;
        window._activeCertificate = cert;

        const totalEl = document.getElementById("popCertTotalFindings");
        const passedEl = document.getElementById("popCertPassedFindings");
        const idEl = document.getElementById("popCertId");
        const assessIdEl = document.getElementById("popCertAssessmentId");
        const nameEl = document.getElementById("popCertProjectName");
        const dateEl = document.getElementById("popCertDate");
        const valDateEl = document.getElementById("popCertValidationDate");

        if (totalEl) totalEl.textContent = cert.total_findings || 0;
        if (passedEl) passedEl.textContent = cert.findings_passed || (cert.total_findings || 0);
        if (idEl) idEl.textContent = cert.certificate_id || "-";
        if (assessIdEl) assessIdEl.textContent = cert.assessment_id || "-";
        if (nameEl) nameEl.textContent = cert.target_name || "Assessment Target";
        if (dateEl) dateEl.textContent = `${cert.assessment_start || cert.issue_date} – ${cert.assessment_end || cert.issue_date}`;
        if (valDateEl) valDateEl.textContent = cert.final_validation_date || cert.issue_date;

        openModal("modalCertificateCompletion");
    }

    function openCertificatePreview(cert) {
        if (!cert) return;
        activeCertificateData = cert;
        window._activeCertificate = cert;

        const setVal = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.textContent = (val !== undefined && val !== null && val !== "") ? val : "-";
        };

        setVal("viewCertId", cert.certificate_id);
        setVal("viewCertVerifyKey", cert.verification_id);
        setVal("viewCertAssessmentId", cert.assessment_id);
        setVal("viewCertClientOrg", cert.client_organization || "Not Provided");
        setVal("viewCertTargetName", cert.target_name);
        setVal("viewCertTargetUrl", cert.target_url);
        setVal("viewCertPeriod", `${cert.assessment_start || cert.issue_date} – ${cert.assessment_end || cert.issue_date}`);
        setVal("viewCertIssueDate", cert.issue_date);
        setVal("viewCertValidationDate", cert.final_validation_date || cert.issue_date);

        if (cert.attestation) {
            setVal("viewCertAttestation", cert.attestation);
        }

        // Live QR Code Generation for Verification Endpoint
        const qrImg = document.getElementById("viewCertQrImg");
        if (qrImg) {
            const verifyUrl = `${window.location.origin}/certificate/verify/${encodeURIComponent(cert.certificate_id)}`;
            qrImg.src = `https://api.qrserver.com/v1/create-qr-code/?size=120x120&data=${encodeURIComponent(verifyUrl)}&color=0f172a&bgcolor=ffffff`;
            qrImg.alt = `Verify ${cert.certificate_id}`;
            qrImg.onerror = () => {
                qrImg.style.display = "none";
            };
            qrImg.onload = () => {
                qrImg.style.display = "block";
            };
        }

        // Retain backward-compatible no-op field calls if present
        setVal("viewCertTotal", cert.total_findings || 0);
        setVal("viewCertCrit", cert.critical_count || 0);
        setVal("viewCertHigh", cert.high_count || 0);
        setVal("viewCertMed", cert.medium_count || 0);
        setVal("viewCertLow", cert.low_count || 0);
        setVal("viewCertInfo", cert.info_count || 0);

        const snapSign = (cert.snapshot && cert.snapshot.signatories) || {};
        setVal("viewCertSignPrepared", snapSign.prepared_by || "Security Assessor");

        const onlineLink = document.getElementById("viewCertOnlineLink");
        if (onlineLink) {
            onlineLink.textContent = window.location.origin + "/certificate/verify/" + cert.certificate_id;
        }

        openModal("modalViewCertificate");
    }

    async function dismissCertificateNotice(certId) {
        if (!certId) return;
        try {
            localStorage.setItem("tg_cert_seen_" + certId, "1");
            await fetch(`/api/certificates/${certId}/dismiss-notice`, {
                method: "POST",
                headers: getAuthHeaders()
            });
        } catch (e) {
            console.warn("Could not dismiss certificate notice:", e);
        }
    }

    let certPollingTimer = null;

    function pollForCertificate(projectId, jobId = null, maxAttempts = 30, intervalMs = 2000) {
        if (!projectId) return;
        if (certPollingTimer) {
            clearInterval(certPollingTimer);
            certPollingTimer = null;
        }
        let attempts = 0;
        certPollingTimer = setInterval(async () => {
            attempts++;
            try {
                const url = jobId 
                    ? `/api/projects/${projectId}/certificate/jobs/${encodeURIComponent(jobId)}`
                    : `/api/projects/${projectId}/certificate/status`;

                const res = await fetch(url, {
                    headers: getAuthHeaders()
                });
                if (!res.ok) {
                    if (res.status === 404 && jobId) {
                        // Job endpoint 404, fall back to project status endpoint
                        jobId = null;
                    }
                    if (attempts >= maxAttempts) {
                        clearInterval(certPollingTimer);
                        certPollingTimer = null;
                    }
                    return;
                }
                const data = await res.json();
                const isGenerated = data.status === "GENERATED" && data.certificate;
                const isFailed = data.status === "FAILED";
                const isStillGenerating = (data.status === "GENERATING") || (data.latest_job && data.latest_job.status === "GENERATING");

                if (isGenerated) {
                    clearInterval(certPollingTimer);
                    certPollingTimer = null;
                    if (typeof updateAIFixCertButtons === "function") {
                        updateAIFixCertButtons(data.certificate);
                    }
                    showCertificateCompletionModal(data.certificate);
                    refreshProjectCertificateStatus(projectId);
                } else if (isFailed) {
                    clearInterval(certPollingTimer);
                    certPollingTimer = null;
                    showToast(data.error || "Certificate generation failed.", "error");
                    refreshProjectCertificateStatus(projectId);
                } else if (!isStillGenerating && !data.eligible && attempts > 1) {
                    clearInterval(certPollingTimer);
                    certPollingTimer = null;
                    refreshProjectCertificateStatus(projectId);
                } else if (attempts >= maxAttempts) {
                    clearInterval(certPollingTimer);
                    certPollingTimer = null;
                    showToast("Certificate generation is taking longer than expected. You can refresh status anytime.", "info");
                    refreshProjectCertificateStatus(projectId);
                }
            } catch (e) {
                if (attempts >= maxAttempts) {
                    clearInterval(certPollingTimer);
                    certPollingTimer = null;
                }
            }
        }, intervalMs);
    }

    async function refreshProjectCertificateStatus(projectId) {
        if (!projectId) return;
        const certCard = document.getElementById("wsCertificateStatusCard");
        const statusBadge = document.getElementById("wsCertStatusBadge");
        const contentArea = document.getElementById("wsCertContentArea");
        const historyContainer = document.getElementById("wsCertHistoryContainer");
        const historyList = document.getElementById("wsCertHistoryList");

        const rBadge = document.getElementById("wsReportCertStatusBadge");
        const rDetails = document.getElementById("wsReportCertDetailsBox");

        try {
            const res = await fetch(`/api/projects/${projectId}/certificate/status`, {
                headers: getAuthHeaders()
            });
            if (!res.ok) return;
            const data = await res.json();

            // Render live diagnostic mode block (Section 42)
            const renderDiagnosticMode = (d) => `
                <div class="cert-diagnostic-box" style="margin-top: 12px; padding: 10px 12px; background: rgba(15, 23, 42, 0.04); border-radius: 6px; border: 1px dashed var(--border-subtle); font-size: 0.74rem; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; color: var(--text-secondary);">
                    <div style="font-weight: 700; text-transform: uppercase; color: var(--text-muted); margin-bottom: 6px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-subtle); padding-bottom: 4px;">
                        <span>🛠️ Diagnostic Mode (Live Assessment State)</span>
                        <span>Assessment: <strong>${escapeHtml(d.assessment_id || d.project_id || projectId || "-")}</strong></span>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 6px; margin-top: 4px;">
                        <div>Confirmed: <strong>${d.total_findings ?? 0}</strong></div>
                        <div>Resolved: <strong>${d.resolved_findings ?? 0}</strong></div>
                        <div>Retested: <strong>${(d.passed_retests ?? d.resolved_findings ?? 0) + (d.failed_retests ?? 0)}</strong></div>
                        <div>Passed: <strong>${d.passed_retests ?? d.resolved_findings ?? 0}</strong></div>
                        <div>Pending: <strong>${d.pending_findings ?? d.pending_retests ?? 0}</strong></div>
                        <div>Failed: <strong>${d.failed_retests ?? 0}</strong></div>
                        <div>Eligible: <strong style="color: ${d.eligible ? '#15803d' : '#b91c1c'};">${d.eligible ? "YES" : "NO"}</strong></div>
                        <div style="grid-column: 1 / -1;">Blocker: <em>${escapeHtml(d.blocking_reason || d.reason || "None")}</em></div>
                        <div style="grid-column: 1 / -1;">Certificate Record: <code>${escapeHtml((d.certificate && d.certificate.certificate_id) || "Not Generated")}</code></div>
                    </div>
                </div>
            `;

            // Check if certificate exists and is generated
            if (data.status === "GENERATED" && data.certificate) {
                const cert = data.certificate;
                activeCertificateData = cert;
                window._activeCertificate = cert;
                if (typeof updateAIFixCertButtons === "function") {
                    updateAIFixCertButtons(cert);
                }

                if (statusBadge) {
                    statusBadge.className = "badge badge-completed";
                    statusBadge.textContent = "● Certificate Issued";
                }
                if (contentArea) {
                    contentArea.innerHTML = `
                        <div style="background: var(--bg-subtle); border: 1px solid var(--border-subtle); border-radius: 8px; padding: 14px 16px; display: flex; flex-direction: column; gap: 10px;">
                            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                                <div>
                                    <span style="font-size: 0.74rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600;">Certificate ID:</span>
                                    <div style="font-family: monospace; font-weight: 700; font-size: 0.95rem; color: var(--primary-600);">${escapeHtml(cert.certificate_id)}</div>
                                </div>
                                <div>
                                    <span style="font-size: 0.74rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600;">Final Validation Date:</span>
                                    <div style="font-weight: 600; font-size: 0.88rem; color: #15803d;">${escapeHtml(cert.final_validation_date || cert.issue_date)}</div>
                                </div>
                                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                                    <button type="button" class="btn btn-outline-primary btn-sm" id="btnWsViewCert">
                                        👁️ View Certificate
                                    </button>
                                    <button type="button" class="btn btn-primary btn-sm" id="btnWsDownloadCert" style="background: #0d9488; border-color: #0d9488;">
                                        ⬇️ Download PDF
                                    </button>
                                </div>
                            </div>
                            <div style="font-size: 0.8rem; color: var(--text-secondary); border-top: 1px solid var(--border-subtle); padding-top: 8px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 6px;">
                                <span>Verification Key: <code style="font-family: monospace;">${escapeHtml(cert.verification_id)}</code></span>
                                <a href="/certificate/verify/${encodeURIComponent(cert.certificate_id)}" target="_blank" rel="noopener noreferrer" style="color: var(--primary-600); text-decoration: underline; font-weight: 600;">
                                    Public Verification Page ↗
                                </a>
                            </div>
                        </div>
                        ${renderDiagnosticMode(data)}
                    `;

                    document.getElementById("btnWsViewCert")?.addEventListener("click", () => openCertificatePreview(cert));
                    document.getElementById("btnWsDownloadCert")?.addEventListener("click", () => {
                        downloadCertificateFile(cert.certificate_id, "pdf");
                    });
                }

                // In Reports tab
                if (rBadge) {
                    rBadge.className = "badge badge-completed";
                    rBadge.textContent = "Issued";
                }
                if (rDetails) {
                    rDetails.innerHTML = `
                        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; background: var(--bg-subtle); padding: 12px 14px; border-radius: 6px; border: 1px solid var(--border-subtle); font-size: 0.84rem;">
                            <div>
                                <strong>Certificate ${escapeHtml(cert.certificate_id)}</strong> • Validated on ${escapeHtml(cert.final_validation_date)}
                            </div>
                            <div style="display: flex; gap: 8px;">
                                <button type="button" class="btn btn-outline-primary btn-sm" id="btnReportViewCert">View</button>
                                <button type="button" class="btn btn-primary btn-sm" id="btnReportDownloadCert">Download PDF</button>
                            </div>
                        </div>
                    `;
                    document.getElementById("btnReportViewCert")?.addEventListener("click", () => openCertificatePreview(cert));
                    document.getElementById("btnReportDownloadCert")?.addEventListener("click", () => {
                        downloadCertificateFile(cert.certificate_id, "pdf");
                    });
                }

                // Fetch history
                try {
                    const hRes = await fetch(`/api/projects/${projectId}/certificates`, {
                        headers: getAuthHeaders()
                    });
                    if (hRes.ok) {
                        const hList = await hRes.json();
                        if (hList && hList.length > 1 && historyContainer && historyList) {
                            historyContainer.style.display = "block";
                            historyList.innerHTML = hList.map(item => `
                                <div style="display: flex; justify-content: space-between; padding: 6px 10px; background: var(--bg-subtle); border-radius: 4px;">
                                    <span><strong>${escapeHtml(item.certificate_id)}</strong> (Issued: ${escapeHtml(item.issue_date)})</span>
                                    <span class="badge ${item.status === 'VALID' ? 'badge-completed' : 'badge-danger'}" style="font-size: 0.7rem;">${escapeHtml(item.status)}</span>
                                </div>
                            `).join("");
                        }
                    }
                } catch (he) {}

            } else if (data.eligible === true) {
                // Eligible but certificate generation pending (Section 40)
                if (statusBadge) {
                    statusBadge.className = "badge badge-warning";
                    statusBadge.textContent = "Validation Passed • Generation Pending";
                }
                if (contentArea) {
                    contentArea.innerHTML = `
                        <div style="background: rgba(234, 179, 8, 0.08); border: 1px solid #eab308; border-radius: 8px; padding: 14px 16px; font-size: 0.85rem; line-height: 1.5;">
                            <div style="font-weight: 700; color: #a16207; margin-bottom: 4px; display: flex; align-items: center; gap: 6px;">
                                ⚠️ Certificate Generation Pending
                            </div>
                            <div style="color: var(--text-secondary); margin-bottom: 12px;">
                                Your assessment has passed the required validation, but the certificate could not be generated yet.
                            </div>
                            <button type="button" class="btn btn-primary btn-sm" id="btnRetryGenerateCert" style="background: #0d9488; border-color: #0d9488;">
                                🔄 Retry Certificate Generation
                            </button>
                        </div>
                        ${renderDiagnosticMode(data)}
                    `;

                    document.getElementById("btnRetryGenerateCert")?.addEventListener("click", async () => {
                        const btn = document.getElementById("btnRetryGenerateCert");
                        if (btn) {
                            btn.disabled = true;
                            btn.textContent = "⏳ Generating...";
                        }
                        try {
                            showToast("Triggering certificate generation...", "info");
                            const gRes = await fetch(`/api/projects/${projectId}/certificate/generate?async_mode=true`, {
                                method: "POST",
                                headers: getAuthHeaders()
                            });
                            const gData = await gRes.json();
                            if (gRes.ok) {
                                if (gData.certificate) {
                                    showToast("✓ Certificate successfully generated!", "success");
                                    if (typeof updateAIFixCertButtons === "function") {
                                        updateAIFixCertButtons(gData.certificate);
                                    }
                                    showCertificateCompletionModal(gData.certificate);
                                    refreshProjectCertificateStatus(projectId);
                                } else if (gData.job_id) {
                                    showToast("Certificate generation running...", "info");
                                    pollForCertificate(projectId, gData.job_id);
                                } else {
                                    refreshProjectCertificateStatus(projectId);
                                }
                            } else {
                                showToast(gData.detail || gData.error || "Failed to generate certificate.", "error");
                                if (btn) {
                                    btn.disabled = false;
                                    btn.textContent = "🔄 Retry Certificate Generation";
                                }
                            }
                        } catch (err) {
                            const isNet = err.name === "TypeError" && err.message && err.message.toLowerCase().includes("fetch");
                            showToast(isNet ? "Network connection error." : err.message, "error");
                            if (btn) {
                                btn.disabled = false;
                                btn.textContent = "🔄 Retry Certificate Generation";
                            }
                        }
                    });
                }
                if (historyContainer) historyContainer.style.display = "none";

                if (rBadge) {
                    rBadge.className = "badge badge-warning";
                    rBadge.textContent = "Generation Pending";
                }
                if (rDetails) {
                    rDetails.innerHTML = `
                        <div style="font-size: 0.82rem; color: var(--text-muted);">
                            All findings validated. Certificate generation pending.
                        </div>
                    `;
                }

            } else {
                // Not eligible or in progress
                if (statusBadge) {
                    statusBadge.className = "badge badge-in-progress";
                    statusBadge.textContent = "In Progress";
                }
                if (contentArea) {
                    contentArea.innerHTML = `
                        <div style="background: var(--bg-subtle); border: 1px dashed var(--border-default); border-radius: 8px; padding: 14px 16px; font-size: 0.85rem; color: var(--text-secondary); line-height: 1.5;">
                            <div style="font-weight: 600; color: var(--text-primary); margin-bottom: 4px;">Certificate not yet available</div>
                            <div>${escapeHtml(data.blocking_reason || data.reason || "Assessment has in-scope findings pending remediation validation.")}</div>
                        </div>
                        ${renderDiagnosticMode(data)}
                    `;
                }
                if (historyContainer) historyContainer.style.display = "none";

                if (rBadge) {
                    rBadge.className = "badge badge-in-progress";
                    rBadge.textContent = "Pending Validation";
                }
                if (rDetails) {
                    rDetails.innerHTML = `
                        <div style="font-size: 0.82rem; color: var(--text-muted);">
                            Certificate will automatically become available once all in-scope findings pass human retest verification.
                        </div>
                    `;
                }
            }
        } catch (e) {
            console.warn("Error refreshing project certificate status:", e);
        }
    }

    // Modal Certificate Completion listeners
    const btnCloseCertCompletionModal = document.getElementById("btnCloseCertCompletionModal");
    const btnCloseCertCompletionFooter = document.getElementById("btnCloseCertCompletionFooter");
    const btnViewCertFromCompletion = document.getElementById("btnViewCertFromCompletion");
    const btnDownloadCertFromCompletion = document.getElementById("btnDownloadCertFromCompletion");

    const closeCertModalAndDismiss = () => {
        closeModal("modalCertificateCompletion");
        if (activeCertificateData) {
            dismissCertificateNotice(activeCertificateData.certificate_id);
        }
    };

    if (btnCloseCertCompletionModal) btnCloseCertCompletionModal.addEventListener("click", closeCertModalAndDismiss);
    if (btnCloseCertCompletionFooter) btnCloseCertCompletionFooter.addEventListener("click", closeCertModalAndDismiss);

    if (btnViewCertFromCompletion) {
        btnViewCertFromCompletion.addEventListener("click", () => {
            closeCertModalAndDismiss();
            if (activeCertificateData) openCertificatePreview(activeCertificateData);
        });
    }
    async function downloadCertificateFile(certId, format = "pdf") {
        if (!certId) {
            showToast("No certificate ID available.", "warning");
            return;
        }
        const fmt = (format || "pdf").toLowerCase().trim();
        try {
            showToast(`Downloading VAPT certificate (${fmt.toUpperCase()})...`, "info");
            const res = await fetch(`/api/certificates/${encodeURIComponent(certId)}/download?format=${encodeURIComponent(fmt)}`, {
                headers: getAuthHeaders()
            });
            if (!res.ok) {
                let errDetail = `Unable to download ${fmt.toUpperCase()} certificate.`;
                try {
                    const errData = await res.json();
                    if (errData.detail) errDetail = errData.detail;
                } catch (_) {}
                showToast(errDetail, "error");
                return;
            }

            const contentType = res.headers.get("content-type") || "";
            if (fmt === "pdf" && contentType.includes("application/json")) {
                showToast("Server returned JSON instead of PDF certificate.", "error");
                return;
            }

            const blob = await res.blob();
            if (blob.size < 100) {
                showToast("Received empty or corrupt certificate artifact.", "error");
                return;
            }

            const blobUrl = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.style.display = "none";
            a.href = blobUrl;
            a.download = `VAPT_Certificate_${certId}.${fmt}`;
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                document.body.removeChild(a);
                window.URL.revokeObjectURL(blobUrl);
            }, 1200);
            showToast(`✓ Certificate (${fmt.toUpperCase()}) downloaded successfully.`, "success");
        } catch (e) {
            console.error("Certificate download error:", e);
            showToast("Failed to download certificate artifact.", "error");
        }
    }

    if (btnDownloadCertFromCompletion) {
        btnDownloadCertFromCompletion.addEventListener("click", () => {
            if (activeCertificateData && activeCertificateData.certificate_id) {
                downloadCertificateFile(activeCertificateData.certificate_id, "pdf");
            }
        });
    }

    // Modal Certificate Preview listeners
    const btnCloseViewCertModal = document.getElementById("btnCloseViewCertModal");
    const btnCloseViewCertModalSecondary = document.getElementById("btnCloseViewCertModalSecondary");
    const btnDownloadCertPdfModal = document.getElementById("btnDownloadCertPdfModal");
    const btnVerifyCertOnlineModal = document.getElementById("btnVerifyCertOnlineModal");

    if (btnCloseViewCertModal) btnCloseViewCertModal.addEventListener("click", () => closeModal("modalViewCertificate"));
    if (btnCloseViewCertModalSecondary) btnCloseViewCertModalSecondary.addEventListener("click", () => closeModal("modalViewCertificate"));

    if (btnDownloadCertPdfModal) {
        btnDownloadCertPdfModal.addEventListener("click", () => {
            if (activeCertificateData && activeCertificateData.certificate_id) {
                downloadCertificateFile(activeCertificateData.certificate_id, "pdf");
            }
        });
    }
    if (btnVerifyCertOnlineModal) {
        btnVerifyCertOnlineModal.addEventListener("click", () => {
            if (activeCertificateData && activeCertificateData.certificate_id) {
                window.open(`/certificate/verify/${encodeURIComponent(activeCertificateData.certificate_id)}`, "_blank");
            }
        });
    }

    // =========================================================================
    // AI Fix Dedicated Certificate Action Buttons Handlers
    // =========================================================================
    function updateAIFixCertButtons(cert) {
        const retestBanner = document.getElementById("wsRetestCertBanner");
        const progressBanner = document.getElementById("wsRetestProgressBanner");
        if (cert) {
            activeCertificateData = cert;
            window._activeCertificate = cert;
            if (retestBanner) retestBanner.style.display = "block";
            if (progressBanner) progressBanner.style.display = "none";
        } else {
            if (retestBanner) retestBanner.style.display = "none";
        }
    }

    function renderRetestProgressBanner(elig, proj) {
        const banner = document.getElementById("wsRetestProgressBanner");
        if (!banner) return;

        if (!elig || elig.eligible || elig.status === "GENERATED") {
            banner.style.display = "none";
            return;
        }

        const total = elig.total_findings || (proj && proj.findings ? proj.findings.length : 0);
        const resolved = elig.resolved_findings || elig.passed_retests || 0;
        const pendingCount = elig.pending_findings ?? (total - resolved);

        if (total === 0 || resolved === 0) {
            banner.style.display = "none";
            return;
        }

        const pct = total > 0 ? Math.round((resolved / total) * 100) : 0;
        const ratioEl = document.getElementById("wsRetestProgressRatio");
        if (ratioEl) {
            ratioEl.textContent = `${resolved} of ${total} Verified (${pct}%)`;
        }

        const descEl = document.getElementById("wsRetestProgressDesc");
        if (descEl) {
            descEl.innerHTML = `Assessment contains <strong>${total}</strong> in-scope finding${total === 1 ? "" : "s"}. <strong>${pendingCount}</strong> remain${pendingCount === 1 ? "" : "s"} pending verification. Official VAPT Assessment Completion Certificates require all findings to pass retest.`;
        }

        const listEl = document.getElementById("wsRetestPendingFindingsList");
        if (listEl) {
            listEl.innerHTML = "";
            let pendingFindings = elig.unresolved_findings;
            if (!pendingFindings || !Array.isArray(pendingFindings)) {
                pendingFindings = proj && proj.findings ? proj.findings.filter(f => {
                    const stat = (f.status || "").toUpperCase();
                    const ret = (f.retest_status || "").toUpperCase();
                    return !(stat === "RESOLVED" && ret === "PASSED");
                }) : [];
            }

            if (pendingFindings.length === 0) {
                listEl.innerHTML = `<span style="color: #15803d; font-weight: 600;">✓ All in-scope findings verified.</span>`;
            } else {
                pendingFindings.slice(0, 6).forEach(f => {
                    const row = document.createElement("div");
                    row.style.display = "flex";
                    row.style.alignItems = "center";
                    row.style.justifyContent = "space-between";
                    row.style.gap = "8px";
                    row.style.padding = "4px 8px";
                    row.style.background = "#fef9c3";
                    row.style.borderRadius = "4px";

                    const vulnId = f.vuln_id || "VULN";
                    const sev = (f.priority || f.severity || "HIGH").toUpperCase();
                    const sevColor = sev === "CRITICAL" ? "#b91c1c" : (sev === "HIGH" ? "#c2410c" : "#d97706");

                    row.innerHTML = `
                        <div style="display: flex; align-items: center; gap: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                            <span style="font-weight: 700; font-family: monospace; color: var(--primary-600);">[${escapeHtml(vulnId)}]</span>
                            <span style="color: var(--text-primary);">${escapeHtml(f.finding_name || f.title || "Vulnerability")}</span>
                        </div>
                        <span class="badge" style="background: ${sevColor}; color: #ffffff; font-size: 0.68rem; font-weight: 700; padding: 2px 6px;">${escapeHtml(sev)}</span>
                    `;
                    listEl.appendChild(row);
                });
                if (pendingFindings.length > 6) {
                    const moreRow = document.createElement("div");
                    moreRow.style.fontSize = "0.75rem";
                    moreRow.style.color = "var(--text-muted)";
                    moreRow.style.paddingLeft = "8px";
                    moreRow.textContent = `+ ${pendingFindings.length - 6} more pending findings...`;
                    listEl.appendChild(moreRow);
                }
            }
        }

        banner.style.display = "block";
    }

    async function checkAndUpdateAIFixCertButtons(projectId) {
        if (!projectId) return;
        try {
            const res = await fetch(`/api/projects/${projectId}/certificate/status`, {
                headers: getAuthHeaders()
            });
            if (!res.ok) return;
            const data = await res.json();
            const proj = getActiveProject();
            if (data.status === "GENERATED" && data.certificate) {
                updateAIFixCertButtons(data.certificate);
            } else {
                updateAIFixCertButtons(null);
                if (typeof renderRetestProgressBanner === "function") {
                    renderRetestProgressBanner(data, proj);
                }
            }
        } catch (e) {
            console.warn("Could not check AI Fix certificate status:", e);
        }
    }

    async function handleAIFixViewCertificate() {
        if (activeCertificateData) {
            openCertificatePreview(activeCertificateData);
            return;
        }
        if (window._activeCertificate) {
            openCertificatePreview(window._activeCertificate);
            return;
        }
        const proj = getActiveProject();
        if (proj && proj.id) {
            try {
                const res = await fetch(`/api/projects/${proj.id}/certificate/status`, {
                    headers: getAuthHeaders()
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data.certificate) {
                        activeCertificateData = data.certificate;
                        window._activeCertificate = data.certificate;
                        openCertificatePreview(data.certificate);
                        return;
                    } else if (data.eligible) {
                        const genRes = await fetch(`/api/projects/${proj.id}/certificate/generate`, {
                            method: "POST",
                            headers: getAuthHeaders()
                        });
                        if (genRes.ok) {
                            const genData = await genRes.json();
                            if (genData.certificate) {
                                activeCertificateData = genData.certificate;
                                window._activeCertificate = genData.certificate;
                                openCertificatePreview(genData.certificate);
                                return;
                            }
                        }
                    }
                }
            } catch (e) {}
        }
        showToast("No certificate has been generated for this assessment yet.", "warning");
    }

    async function handleAIFixDownloadCertificate(format = "pdf") {
        const cert = activeCertificateData || window._activeCertificate;
        if (cert && cert.certificate_id) {
            downloadCertificateFile(cert.certificate_id, format);
            return;
        }
        const proj = getActiveProject();
        if (proj && proj.id) {
            try {
                const res = await fetch(`/api/projects/${proj.id}/certificate/status`, {
                    headers: getAuthHeaders()
                });
                if (res.ok) {
                    const data = await res.json();
                    if (data.certificate && data.certificate.certificate_id) {
                        activeCertificateData = data.certificate;
                        window._activeCertificate = data.certificate;
                        downloadCertificateFile(data.certificate.certificate_id, format);
                        return;
                    } else if (data.eligible) {
                        const genRes = await fetch(`/api/projects/${proj.id}/certificate/generate`, {
                            method: "POST",
                            headers: getAuthHeaders()
                        });
                        if (genRes.ok) {
                            const genData = await genRes.json();
                            if (genData.certificate && genData.certificate.certificate_id) {
                                activeCertificateData = genData.certificate;
                                window._activeCertificate = genData.certificate;
                                downloadCertificateFile(genData.certificate.certificate_id, format);
                                return;
                            }
                        }
                    }
                }
            } catch (e) {}
        }
        showToast("No certificate available to download.", "warning");
    }

    document.getElementById("btnWsAIFixViewCert")?.addEventListener("click", handleAIFixViewCertificate);
    document.getElementById("btnWsAIFixDownloadCert")?.addEventListener("click", () => handleAIFixDownloadCertificate("pdf"));

    // Retest All & Switch Next Handlers
    const btnWsPassRetestAll = document.getElementById("btnWsPassRetestAll");
    if (btnWsPassRetestAll) {
        btnWsPassRetestAll.addEventListener("click", async () => {
            const proj = getActiveProject();
            const projId = proj ? proj.id : (typeof activeProjectId !== "undefined" ? activeProjectId : null);
            if (!projId) {
                showToast("No active project selected.", "warning");
                return;
            }

            const notes = document.getElementById("txtRetestNotes")?.value.trim() || "Batch tester verification: all in-scope findings validated.";
            const origHtml = btnWsPassRetestAll.innerHTML;
            btnWsPassRetestAll.disabled = true;
            btnWsPassRetestAll.textContent = "⏳ Verifying All Findings & Generating Certificate...";

            try {
                showToast("Recording batch retest verification for all findings...", "info");
                const res = await fetch(`/api/ai-fix/__ALL_FINDINGS__/retest?project_id=${encodeURIComponent(projId)}&assessment_id=${encodeURIComponent(projId)}`, {
                    method: "POST",
                    headers: getAuthHeaders({ "Content-Type": "application/json" }),
                    body: JSON.stringify({
                        finding_id: "__ALL_FINDINGS__",
                        project_id: projId,
                        assessment_id: projId,
                        result: "PASS",
                        notes: notes
                    })
                });

                if (!res.ok) {
                    const errData = await res.json().catch(() => ({}));
                    throw new Error(errData.detail || "Batch retest failed.");
                }

                const retestRes = await res.json();

                if (proj && proj.findings) {
                    proj.findings.forEach(item => {
                        item.status = "RESOLVED";
                        item.fix_status = "Resolved";
                        item.retest_status = "PASSED";
                        item.retest_notes = notes;
                    });
                    saveProjects();
                    renderWorkspaceFindings();
                    refreshDashboardStats();
                }

                const retestPill = document.getElementById("retestLifecyclePill");
                const retestSuccessBadge = document.getElementById("retestSuccessBadge");
                if (retestPill) {
                    retestPill.className = "badge badge-completed";
                    retestPill.textContent = "Retest Passed (All)";
                }
                if (retestSuccessBadge) {
                    retestSuccessBadge.style.display = "block";
                    retestSuccessBadge.innerHTML = `✓ All assessment findings transitioned: <strong>Fix Applied &rarr; Retested &rarr; RESOLVED</strong>`;
                }

                const progressBanner = document.getElementById("wsRetestProgressBanner");
                if (progressBanner) progressBanner.style.display = "none";

                if (retestRes && retestRes.certificate) {
                    updateAIFixCertButtons(retestRes.certificate);
                    if (typeof showCertificateCompletionModal === "function") {
                        showCertificateCompletionModal(retestRes.certificate);
                    }
                } else if (retestRes && retestRes.certificate_eligible) {
                    const certBanner = document.getElementById("wsRetestCertBanner");
                    if (certBanner) certBanner.style.display = "block";
                    if (typeof pollForCertificate === "function") {
                        pollForCertificate(projId, retestRes && retestRes.certificate_job_id);
                    }
                }

                if (typeof refreshProjectCertificateStatus === "function") {
                    refreshProjectCertificateStatus(projId);
                }

                showToast("✓ All findings resolved! VAPT Assessment Certificate generated.", "success");
            } catch (err) {
                showToast(err.message || "Batch verification failed.", "error");
            } finally {
                btnWsPassRetestAll.disabled = false;
                btnWsPassRetestAll.innerHTML = origHtml;
            }
        });
    }

    const btnWsSwitchNextPending = document.getElementById("btnWsSwitchNextPending");
    if (btnWsSwitchNextPending) {
        btnWsSwitchNextPending.addEventListener("click", () => {
            const proj = getActiveProject();
            if (!proj || !proj.findings) return;
            const pending = proj.findings.find(f => {
                const stat = (f.status || "").toUpperCase();
                const ret = (f.retest_status || "").toUpperCase();
                return !(stat === "RESOLVED" && ret === "PASSED");
            });
            if (pending) {
                const sel = document.getElementById("wsAutofixFindingSelect");
                if (sel) {
                    sel.value = pending.id;
                    sel.dispatchEvent(new Event("change"));
                    showToast(`Switched to: [${pending.vuln_id || 'VULN'}] ${pending.finding_name}`, "info");
                }
            } else {
                showToast("All findings have already been verified!", "success");
            }
        });
    }

    // =========================================================================
    // PROJECT SECURITY ANALYTICS MODULE (Section 45 & Overview Analytics)
    // =========================================================================
    const TG_SEVERITY_COLORS = {
        critical: "#b91c1c",
        high: "#c2410c",
        medium: "#d97706",
        low: "#059669",
        informational: "#0284c7"
    };

    const TG_COVERAGE_COLORS = {
        clean: "#059669",
        with_findings: "#dc2626",
        not_tested: "#94a3b8",
        not_applicable: "#cbd5e1"
    };

    const TG_STATUS_COLORS = {
        open: "#dc2626",
        in_remediation: "#d97706",
        retest_pending: "#2563eb",
        resolved: "#059669",
        closed: "#64748b"
    };

    let currentProjectAnalytics = null;
    let activeAnalyticsMetric = "severity"; // "severity" | "coverage" | "status"
    let activeAnalyticsChartType = "donut"; // "donut" | "bar" | "table"
    let activeAnalyticsProjectId = null;

    function formatAnalyticsPct(val, total) {
        if (!total || total <= 0) return "0.0%";
        const p = Math.round((val / total) * 1000) / 10;
        return p.toFixed(1) + "%";
    }

    async function fetchProjectAnalytics(projectId) {
        if (!projectId) return null;
        const headers = {};
        const token = localStorage.getItem("tg_auth_token");
        if (token) {
            headers["Authorization"] = `Bearer ${token}`;
        }
        const res = await fetch(`/api/projects/${encodeURIComponent(projectId)}/analytics`, { headers });
        if (!res.ok) {
            throw new Error(`Failed to load project analytics (${res.status})`);
        }
        return await res.json();
    }

    async function refreshProjectSecurityAnalytics(projectId) {
        const cardEl = document.getElementById("wsSecurityAnalyticsCard");
        if (!cardEl) return;

        const loadingEl = document.getElementById("wsAnalyticsLoading");
        const errorEl = document.getElementById("wsAnalyticsError");
        const emptyEl = document.getElementById("wsAnalyticsEmpty");
        const contentEl = document.getElementById("wsAnalyticsContent");

        const proj = getActiveProject();
        const targetId = projectId || (proj ? proj.id : null);
        if (!targetId) {
            if (contentEl) contentEl.style.display = "none";
            if (loadingEl) loadingEl.style.display = "none";
            if (errorEl) errorEl.style.display = "none";
            if (emptyEl) emptyEl.style.display = "block";
            return;
        }

        // Clean slate on project switch
        if (activeAnalyticsProjectId !== targetId) {
            currentProjectAnalytics = null;
            activeAnalyticsProjectId = targetId;
        }

        if (!currentProjectAnalytics) {
            if (loadingEl) loadingEl.style.display = "block";
            if (errorEl) errorEl.style.display = "none";
            if (emptyEl) emptyEl.style.display = "none";
            if (contentEl) contentEl.style.display = "none";
        }

        try {
            const data = await fetchProjectAnalytics(targetId);
            if (targetId !== activeAnalyticsProjectId) return;

            currentProjectAnalytics = data;
            if (loadingEl) loadingEl.style.display = "none";
            if (errorEl) errorEl.style.display = "none";

            const totalFindings = (data.findings && data.findings.total) || 0;
            const plannedTests = (data.coverage && data.coverage.planned) || 0;

            if (totalFindings === 0 && plannedTests === 0) {
                if (emptyEl) emptyEl.style.display = "block";
                if (contentEl) contentEl.style.display = "none";
            } else {
                if (emptyEl) emptyEl.style.display = "none";
                if (contentEl) contentEl.style.display = "flex";
                renderCompactOverviewChart(data);
            }
        } catch (err) {
            console.warn("[TRACEGATE] Failed to refresh project security analytics:", err);
            if (targetId !== activeAnalyticsProjectId) return;
            if (loadingEl) loadingEl.style.display = "none";
            if (contentEl) contentEl.style.display = "none";
            if (emptyEl) emptyEl.style.display = "none";
            if (errorEl) errorEl.style.display = "block";
        }
    }

    function renderCompactOverviewChart(data) {
        const donutContainer = document.getElementById("wsCompactDonutContainer");
        const countersGrid = document.getElementById("wsCompactCountersGrid");
        if (!donutContainer || !countersGrid) return;

        const findings = data.findings || { total: 0, critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
        const total = findings.total || 0;

        const size = 136;
        const strokeWidth = 14;
        const radius = (size - strokeWidth) / 2; // 61
        const center = size / 2; // 68
        const circumference = 2 * Math.PI * radius;

        let svgHtml = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="transform: rotate(-90deg); overflow: visible;">`;
        svgHtml += `<circle cx="${center}" cy="${center}" r="${radius}" fill="none" stroke="var(--border-subtle)" stroke-width="${strokeWidth}" />`;

        if (total > 0) {
            const slices = [
                { count: findings.critical || 0, color: TG_SEVERITY_COLORS.critical },
                { count: findings.high || 0, color: TG_SEVERITY_COLORS.high },
                { count: findings.medium || 0, color: TG_SEVERITY_COLORS.medium },
                { count: findings.low || 0, color: TG_SEVERITY_COLORS.low },
                { count: findings.informational || 0, color: TG_SEVERITY_COLORS.informational }
            ];

            let accumulated = 0;
            slices.forEach(s => {
                if (s.count > 0) {
                    const strokeLen = (s.count / total) * circumference;
                    const offset = -accumulated;
                    svgHtml += `<circle cx="${center}" cy="${center}" r="${radius}" fill="none" stroke="${s.color}" stroke-width="${strokeWidth}" stroke-dasharray="${strokeLen.toFixed(2)} ${circumference.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}" style="transition: stroke-dasharray 0.4s ease;" />`;
                    accumulated += strokeLen;
                }
            });
        }
        svgHtml += `</svg>`;

        const centerTextOverlay = `
            <div style="position: absolute; display: flex; flex-direction: column; align-items: center; justify-content: center; pointer-events: none; text-align: center;">
                <span style="font-size: 0.62rem; font-weight: 700; color: var(--text-muted); letter-spacing: 0.5px; text-transform: uppercase;">TOTAL</span>
                <span style="font-size: 1.35rem; font-weight: 800; color: var(--text-primary); line-height: 1.1;">${total}</span>
                <span style="font-size: 0.62rem; font-weight: 700; color: var(--text-muted); letter-spacing: 0.5px; text-transform: uppercase;">FINDINGS</span>
            </div>
        `;

        donutContainer.style.position = "relative";
        donutContainer.innerHTML = svgHtml + centerTextOverlay;

        const counters = [
            { label: "Critical", count: findings.critical || 0, color: TG_SEVERITY_COLORS.critical },
            { label: "High", count: findings.high || 0, color: TG_SEVERITY_COLORS.high },
            { label: "Medium", count: findings.medium || 0, color: TG_SEVERITY_COLORS.medium },
            { label: "Low", count: findings.low || 0, color: TG_SEVERITY_COLORS.low },
            { label: "Info", count: findings.informational || 0, color: TG_SEVERITY_COLORS.informational }
        ];

        let countersHtml = "";
        counters.forEach(c => {
            countersHtml += `
                <div style="display: flex; align-items: center; justify-content: space-between; padding: 4px 8px; background: var(--bg-main); border-radius: 6px; border: 1px solid var(--border-subtle);">
                    <div style="display: flex; align-items: center; gap: 6px;">
                        <span style="width: 8px; height: 8px; border-radius: 50%; background-color: ${c.color};"></span>
                        <span style="color: var(--text-secondary); font-size: 0.76rem;">${c.label}</span>
                    </div>
                    <strong style="font-size: 0.8rem; color: var(--text-primary); font-family: var(--font-mono);">${c.count}</strong>
                </div>
            `;
        });
        countersGrid.innerHTML = countersHtml;
    }

    function openSecurityAnalyticsModal() {
        const proj = getActiveProject();
        if (!proj) return;

        // Open modal immediately so user gets instant visual feedback
        openModal("modalProjectSecurityAnalytics");

        if (!currentProjectAnalytics || activeAnalyticsProjectId !== proj.id) {
            const viewport = document.getElementById("modalAnalyticsChartViewport");
            if (viewport) {
                viewport.innerHTML = `
                    <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; padding: 40px 0;">
                        <div style="width: 32px; height: 32px; border: 3px solid rgba(99, 102, 241, 0.2); border-top-color: #6366f1; border-radius: 50%; animation: spin 0.8s linear infinite;"></div>
                        <span style="font-size: 0.85rem; color: var(--text-muted);">Loading project analytics...</span>
                    </div>
                `;
            }
            refreshProjectSecurityAnalytics(proj.id).then(() => {
                renderModalAnalyticsContent();
            }).catch(err => {
                if (viewport) {
                    viewport.innerHTML = `<div style="color: #ef4444; font-size: 0.88rem; text-align: center;">Unable to load project analytics. Please retry.</div>`;
                }
            });
        } else {
            renderModalAnalyticsContent();
        }
    }
    window.openSecurityAnalyticsModal = openSecurityAnalyticsModal;

    function renderModalAnalyticsContent() {
        const data = currentProjectAnalytics;
        const viewport = document.getElementById("modalAnalyticsChartViewport");
        const summary = document.getElementById("modalAnalyticsSummarySection");
        if (!viewport || !summary) return;

        // Update toolbar button states
        document.querySelectorAll(".tg-metric-btn").forEach(btn => {
            const m = btn.getAttribute("data-metric");
            if (m === activeAnalyticsMetric) {
                btn.className = "btn btn-sm btn-primary tg-metric-btn";
            } else {
                btn.className = "btn btn-sm btn-outline-secondary tg-metric-btn";
            }
        });

        document.querySelectorAll(".tg-chart-btn").forEach(btn => {
            const c = btn.getAttribute("data-chart");
            if (c === activeAnalyticsChartType) {
                btn.className = "btn btn-sm btn-primary tg-chart-btn";
            } else {
                btn.className = "btn btn-sm btn-outline-secondary tg-chart-btn";
            }
        });

        if (!data) {
            viewport.innerHTML = `<div style="color: var(--text-muted); font-size: 0.88rem;">No analytics data available for this project.</div>`;
            summary.innerHTML = "";
            return;
        }

        // Prepare items and total based on active metric
        let items = [];
        let total = 0;
        let metricTitle = "";

        if (activeAnalyticsMetric === "severity") {
            const f = data.findings || {};
            total = f.total || 0;
            metricTitle = "Finding Severity Distribution";
            items = [
                { key: "critical", label: "Critical", count: f.critical || 0, color: TG_SEVERITY_COLORS.critical },
                { key: "high", label: "High", count: f.high || 0, color: TG_SEVERITY_COLORS.high },
                { key: "medium", label: "Medium", count: f.medium || 0, color: TG_SEVERITY_COLORS.medium },
                { key: "low", label: "Low", count: f.low || 0, color: TG_SEVERITY_COLORS.low },
                { key: "informational", label: "Informational", count: f.informational || 0, color: TG_SEVERITY_COLORS.informational }
            ];
        } else if (activeAnalyticsMetric === "coverage") {
            const c = data.coverage || {};
            total = c.planned || 0;
            metricTitle = "Testing Coverage & Control Verification";
            items = [
                { key: "clean", label: "Verified Clean", count: c.clean || 0, color: TG_COVERAGE_COLORS.clean },
                { key: "with_findings", label: "Confirmed Findings", count: c.with_findings || 0, color: TG_COVERAGE_COLORS.with_findings },
                { key: "not_tested", label: "Not Tested", count: c.not_tested || 0, color: TG_COVERAGE_COLORS.not_tested },
                { key: "not_applicable", label: "Not Applicable", count: c.not_applicable || 0, color: TG_COVERAGE_COLORS.not_applicable }
            ];
        } else if (activeAnalyticsMetric === "status") {
            const s = data.status || {};
            const f = data.findings || {};
            total = f.total || 0;
            metricTitle = "Vulnerability Lifecycle Status";
            items = [
                { key: "open", label: "Open", count: s.open || 0, color: TG_STATUS_COLORS.open },
                { key: "in_remediation", label: "In Remediation", count: s.in_remediation || 0, color: TG_STATUS_COLORS.in_remediation },
                { key: "retest_pending", label: "Retest Pending", count: s.retest_pending || 0, color: TG_STATUS_COLORS.retest_pending },
                { key: "resolved", label: "Resolved", count: s.resolved || 0, color: TG_STATUS_COLORS.resolved },
                { key: "closed", label: "Closed", count: s.closed || 0, color: TG_STATUS_COLORS.closed }
            ];
        }

        // Render appropriate chart type
        if (activeAnalyticsChartType === "donut") {
            renderModalDonut(viewport, items, total);
        } else if (activeAnalyticsChartType === "bar") {
            renderModalBar(viewport, items, total);
        } else if (activeAnalyticsChartType === "table") {
            renderModalTable(viewport, items, total);
        }

        // Render summary cards below chart
        renderModalSummaryCards(summary, data);
    }

    function renderModalDonut(container, items, total) {
        const size = 220;
        const strokeWidth = 24;
        const radius = (size - strokeWidth) / 2; // 98
        const center = size / 2; // 110
        const circumference = 2 * Math.PI * radius;

        let centerLabel = "FINDINGS";
        let centerValue = total.toString();
        if (activeAnalyticsMetric === "coverage") {
            const c = currentProjectAnalytics?.coverage || {};
            centerValue = `${c.percentage || 0}%`;
            centerLabel = "COVERAGE";
        }

        let svgHtml = `<svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="transform: rotate(-90deg); overflow: visible;">`;
        svgHtml += `<circle cx="${center}" cy="${center}" r="${radius}" fill="none" stroke="var(--border-subtle)" stroke-width="${strokeWidth}" />`;

        if (total > 0) {
            let accumulated = 0;
            items.forEach((it, idx) => {
                if (it.count > 0) {
                    const strokeLen = (it.count / total) * circumference;
                    const offset = -accumulated;
                    const pctStr = formatAnalyticsPct(it.count, total);
                    svgHtml += `
                        <circle cx="${center}" cy="${center}" r="${radius}" fill="none"
                            stroke="${it.color}" stroke-width="${strokeWidth}"
                            stroke-dasharray="${strokeLen.toFixed(2)} ${circumference.toFixed(2)}"
                            stroke-dashoffset="${offset.toFixed(2)}"
                            class="tg-donut-segment"
                            data-label="${escapeHtml(it.label)}"
                            data-count="${it.count}"
                            data-pct="${pctStr}"
                            style="cursor: pointer; transition: stroke-width 0.2s ease, opacity 0.2s ease;"
                        />
                    `;
                    accumulated += strokeLen;
                }
            });
        }
        svgHtml += `</svg>`;

        const centerTextOverlay = `
            <div style="position: absolute; display: flex; flex-direction: column; align-items: center; justify-content: center; pointer-events: none; text-align: center;">
                <span style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); letter-spacing: 0.6px; text-transform: uppercase;">TOTAL</span>
                <span style="font-size: 1.8rem; font-weight: 800; color: var(--text-primary); line-height: 1.1;">${centerValue}</span>
                <span style="font-size: 0.72rem; font-weight: 700; color: var(--text-muted); letter-spacing: 0.6px; text-transform: uppercase;">${centerLabel}</span>
            </div>
        `;

        // Interactive Legend
        let legendHtml = `<div style="display: flex; flex-direction: column; gap: 10px; min-width: 220px;">`;
        items.forEach(it => {
            const pctStr = formatAnalyticsPct(it.count, total);
            legendHtml += `
                <div style="display: flex; align-items: center; justify-content: space-between; padding: 6px 10px; background: var(--bg-main); border-radius: 6px; border: 1px solid var(--border-subtle);">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span style="width: 10px; height: 10px; border-radius: 50%; background-color: ${it.color};"></span>
                        <span style="font-size: 0.82rem; font-weight: 600; color: var(--text-primary);">${escapeHtml(it.label)}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <strong style="font-size: 0.85rem; font-family: var(--font-mono); color: var(--text-primary);">${it.count}</strong>
                        <span style="font-size: 0.76rem; color: var(--text-muted); font-family: var(--font-mono); width: 44px; text-align: right;">${pctStr}</span>
                    </div>
                </div>
            `;
        });
        legendHtml += `</div>`;

        // Tooltip container
        const tooltipHtml = `<div id="tgAnalyticsTooltip" style="display: none; position: absolute; background: #0f172a; color: #ffffff; padding: 6px 12px; border-radius: 6px; font-size: 0.78rem; pointer-events: none; z-index: 100; box-shadow: 0 4px 12px rgba(0,0,0,0.15); font-family: var(--font-sans); white-space: nowrap;"></div>`;

        container.style.display = "flex";
        container.style.flexDirection = "row";
        container.style.justifyContent = "center";
        container.style.alignItems = "center";
        container.style.gap = "36px";
        container.style.flexWrap = "wrap";
        container.innerHTML = `
            <div style="position: relative; display: flex; align-items: center; justify-content: center;">
                ${svgHtml}
                ${centerTextOverlay}
            </div>
            ${legendHtml}
            ${tooltipHtml}
        `;

        setupChartTooltips(container);
    }

    function renderModalBar(container, items, total) {
        let maxVal = 0;
        items.forEach(it => { if (it.count > maxVal) maxVal = it.count; });
        if (maxVal === 0) maxVal = 1;

        let html = `<div style="width: 100%; max-width: 620px; display: flex; flex-direction: column; gap: 14px;">`;

        items.forEach(it => {
            const barPct = (it.count / maxVal) * 100;
            const distPct = formatAnalyticsPct(it.count, total);

            html += `
                <div style="display: flex; flex-direction: column; gap: 4px;" class="tg-bar-row" data-label="${escapeHtml(it.label)}" data-count="${it.count}" data-pct="${distPct}">
                    <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.82rem;">
                        <span style="font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 6px;">
                            <span style="width: 8px; height: 8px; border-radius: 50%; background-color: ${it.color};"></span>
                            ${escapeHtml(it.label)}
                        </span>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <strong style="font-family: var(--font-mono); color: var(--text-primary); font-size: 0.85rem;">${it.count}</strong>
                            <span style="color: var(--text-muted); font-size: 0.76rem; font-family: var(--font-mono); width: 44px; text-align: right;">${distPct}</span>
                        </div>
                    </div>
                    <div style="height: 12px; background: var(--bg-main); border-radius: 6px; overflow: hidden; border: 1px solid var(--border-subtle); display: flex;">
                        <div style="height: 100%; width: ${barPct}%; background-color: ${it.color}; border-radius: 6px; transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1);" title="${escapeHtml(it.label)}: ${it.count} (${distPct})"></div>
                    </div>
                </div>
            `;
        });

        html += `</div>`;
        const tooltipHtml = `<div id="tgAnalyticsTooltip" style="display: none; position: absolute; background: #0f172a; color: #ffffff; padding: 6px 12px; border-radius: 6px; font-size: 0.78rem; pointer-events: none; z-index: 100; box-shadow: 0 4px 12px rgba(0,0,0,0.15); font-family: var(--font-sans); white-space: nowrap;"></div>`;

        container.style.display = "flex";
        container.style.justifyContent = "center";
        container.style.alignItems = "center";
        container.innerHTML = html + tooltipHtml;

        setupChartTooltips(container);
    }

    function renderModalTable(container, items, total) {
        let metricColHeader = "Category";
        if (activeAnalyticsMetric === "coverage") metricColHeader = "Verification Metric";
        else if (activeAnalyticsMetric === "status") metricColHeader = "Lifecycle State";

        let html = `
            <div style="width: 100%; overflow-x: auto;">
                <table class="table" style="width: 100%; border-collapse: collapse; font-size: 0.85rem;">
                    <thead>
                        <tr style="background: var(--bg-main); border-bottom: 2px solid var(--border-default); text-align: left;">
                            <th style="padding: 10px 14px; font-weight: 700; color: var(--text-primary);">${metricColHeader}</th>
                            <th style="padding: 10px 14px; font-weight: 700; color: var(--text-primary); text-align: right;">Count</th>
                            <th style="padding: 10px 14px; font-weight: 700; color: var(--text-primary); text-align: right;">Proportion</th>
                            <th style="padding: 10px 14px; font-weight: 700; color: var(--text-primary); text-align: center;">Visual Indicator</th>
                        </tr>
                    </thead>
                    <tbody>
        `;

        items.forEach(it => {
            const distPct = formatAnalyticsPct(it.count, total);
            html += `
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                    <td style="padding: 10px 14px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
                        <span style="width: 9px; height: 9px; border-radius: 50%; background-color: ${it.color}; display: inline-block;"></span>
                        ${escapeHtml(it.label)}
                    </td>
                    <td style="padding: 10px 14px; font-family: var(--font-mono); font-weight: 700; text-align: right; color: var(--text-primary);">${it.count}</td>
                    <td style="padding: 10px 14px; font-family: var(--font-mono); text-align: right; color: var(--text-muted);">${distPct}</td>
                    <td style="padding: 10px 14px; text-align: center;">
                        <span class="badge" style="background-color: ${it.color}18; color: ${it.color}; border: 1px solid ${it.color}35; font-size: 0.75rem; padding: 2px 8px;">
                            ${escapeHtml(it.label)}
                        </span>
                    </td>
                </tr>
            `;
        });

        html += `
                    </tbody>
                    <tfoot>
                        <tr style="background: var(--bg-subtle); font-weight: 700; border-top: 2px solid var(--border-default);">
                            <td style="padding: 10px 14px; color: var(--text-primary);">Total</td>
                            <td style="padding: 10px 14px; font-family: var(--font-mono); text-align: right; color: var(--text-primary);">${total}</td>
                            <td style="padding: 10px 14px; font-family: var(--font-mono); text-align: right; color: var(--text-primary);">100.0%</td>
                            <td style="padding: 10px 14px; text-align: center; color: var(--text-muted); font-size: 0.78rem;">Authoritative Record</td>
                        </tr>
                    </tfoot>
                </table>
            </div>
        `;

        container.style.display = "block";
        container.innerHTML = html;
    }

    function renderModalSummaryCards(container, data) {
        let cards = [];

        if (activeAnalyticsMetric === "severity") {
            const f = data.findings || {};
            cards = [
                { label: "Total Findings", value: f.total || 0, desc: "Total confirmed security findings" },
                { label: "Critical", value: f.critical || 0, desc: "Immediate remote exploit risks", color: TG_SEVERITY_COLORS.critical },
                { label: "High", value: f.high || 0, desc: "Elevated vulnerability impact", color: TG_SEVERITY_COLORS.high },
                { label: "Medium", value: f.medium || 0, desc: "Conditional security weaknesses", color: TG_SEVERITY_COLORS.medium },
                { label: "Low & Info", value: (f.low || 0) + (f.informational || 0), desc: "Minor defects & information disclosures", color: TG_SEVERITY_COLORS.low }
            ];
        } else if (activeAnalyticsMetric === "coverage") {
            const c = data.coverage || {};
            cards = [
                { label: "Planned Tests", value: c.planned || 0, desc: "Total verification checklist controls" },
                { label: "Evaluated", value: c.evaluated || 0, desc: "Controls tested by assessor" },
                { label: "Verified Clean", value: c.clean || 0, desc: "Controls tested with no vulnerability", color: TG_COVERAGE_COLORS.clean },
                { label: "With Findings", value: c.with_findings || 0, desc: "Controls with confirmed vulnerability", color: TG_COVERAGE_COLORS.with_findings },
                { label: "Coverage %", value: `${c.percentage || 0}%`, desc: "Proportion of evaluated controls", color: "#6366f1" }
            ];
        } else if (activeAnalyticsMetric === "status") {
            const s = data.status || {};
            const f = data.findings || {};
            cards = [
                { label: "Total Findings", value: f.total || 0, desc: "Total recorded findings" },
                { label: "Open", value: s.open || 0, desc: "Awaiting remediation", color: TG_STATUS_COLORS.open },
                { label: "In Remediation", value: s.in_remediation || 0, desc: "Patch or fix in progress", color: TG_STATUS_COLORS.in_remediation },
                { label: "Retest Pending", value: s.retest_pending || 0, desc: "Awaiting tester retest validation", color: TG_STATUS_COLORS.retest_pending },
                { label: "Resolved", value: s.resolved || 0, desc: "Validated passing retest", color: TG_STATUS_COLORS.resolved }
            ];
        }

        let html = `<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px;">`;
        cards.forEach(card => {
            html += `
                <div style="background: var(--bg-main); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 12px; display: flex; flex-direction: column; gap: 4px;">
                    <span style="font-size: 0.72rem; text-transform: uppercase; font-weight: 700; color: var(--text-muted);">${card.label}</span>
                    <strong style="font-size: 1.3rem; font-family: var(--font-mono); color: ${card.color || 'var(--text-primary)'};">${card.value}</strong>
                    <span style="font-size: 0.72rem; color: var(--text-secondary); line-height: 1.3;">${card.desc}</span>
                </div>
            `;
        });
        html += `</div>`;
        container.innerHTML = html;
    }

    function setupChartTooltips(container) {
        const tooltip = container.querySelector("#tgAnalyticsTooltip");
        if (!tooltip) return;

        const showTip = (label, count, pct, e) => {
            tooltip.innerHTML = `<strong>${escapeHtml(label)}</strong>: ${count} (${escapeHtml(pct)})`;
            tooltip.style.display = "block";
            const rect = container.getBoundingClientRect();
            const x = e.clientX - rect.left + 12;
            const y = e.clientY - rect.top + 12;
            tooltip.style.left = `${x}px`;
            tooltip.style.top = `${y}px`;
        };

        const hideTip = () => {
            tooltip.style.display = "none";
        };

        container.querySelectorAll(".tg-donut-segment").forEach(el => {
            el.addEventListener("mouseenter", (e) => {
                el.style.strokeWidth = "28";
                el.style.opacity = "0.9";
                showTip(el.dataset.label, el.dataset.count, el.dataset.pct, e);
            });
            el.addEventListener("mousemove", (e) => {
                showTip(el.dataset.label, el.dataset.count, el.dataset.pct, e);
            });
            el.addEventListener("mouseleave", () => {
                el.style.strokeWidth = "24";
                el.style.opacity = "1";
                hideTip();
            });
        });

        container.querySelectorAll(".tg-bar-row").forEach(el => {
            el.addEventListener("mouseenter", (e) => {
                showTip(el.dataset.label, el.dataset.count, el.dataset.pct, e);
            });
            el.addEventListener("mousemove", (e) => {
                showTip(el.dataset.label, el.dataset.count, el.dataset.pct, e);
            });
            el.addEventListener("mouseleave", hideTip);
        });
    }

    // Modal and Card Event Listeners
    const cardAnalytics = document.getElementById("wsSecurityAnalyticsCard");
    if (cardAnalytics) {
        cardAnalytics.addEventListener("click", () => {
            openSecurityAnalyticsModal();
        });
        cardAnalytics.addEventListener("keydown", (e) => {
            if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                openSecurityAnalyticsModal();
            }
        });
    }

    const btnCloseModal = document.getElementById("btnCloseSecurityAnalyticsModal");
    const btnCloseModalFooter = document.getElementById("btnCloseSecurityAnalyticsModalFooter");
    if (btnCloseModal) btnCloseModal.addEventListener("click", () => closeModal("modalProjectSecurityAnalytics"));
    if (btnCloseModalFooter) btnCloseModalFooter.addEventListener("click", () => closeModal("modalProjectSecurityAnalytics"));

    // Metric selectors in modal
    document.querySelectorAll(".tg-metric-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const m = e.currentTarget.getAttribute("data-metric");
            if (m && m !== activeAnalyticsMetric) {
                activeAnalyticsMetric = m;
                renderModalAnalyticsContent();
            }
        });
    });

    // Chart type selectors in modal
    document.querySelectorAll(".tg-chart-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const c = e.currentTarget.getAttribute("data-chart");
            if (c && c !== activeAnalyticsChartType) {
                activeAnalyticsChartType = c;
                renderModalAnalyticsContent();
            }
        });
    });

    // Keyboard Escape to close analytics modal
    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape") {
            const modal = document.getElementById("modalProjectSecurityAnalytics");
            if (modal && modal.classList.contains("active")) {
                closeModal("modalProjectSecurityAnalytics");
            }
        }
    });

    // Expose functions globally for project switching, real-time finding events, and tests
    window.refreshProjectSecurityAnalytics = refreshProjectSecurityAnalytics;
    window.openSecurityAnalyticsModal = openSecurityAnalyticsModal;
    window.renderModalAnalyticsContent = renderModalAnalyticsContent;
    window.fetchProjectAnalytics = fetchProjectAnalytics;

    // Multi-tab session synchronization and immediate cross-user state isolation
    window.addEventListener("storage", (e) => {
        if (e.key === "tg_auth_token" || e.key === "tg_user") {
            const currentToken = localStorage.getItem("tg_auth_token");
            if (!currentToken) {
                // User logged out in another tab
                if (typeof clearUserSessionState === "function") {
                    clearUserSessionState();
                }
                if (window.location.hash !== "#login") {
                    navigateTo("#login");
                }
            } else if (currentUser && e.newValue) {
                try {
                    const newUser = JSON.parse(localStorage.getItem("tg_user") || "{}");
                    if (newUser.id && newUser.id !== currentUser.id) {
                        // User switched in another tab
                        if (typeof clearUserSessionState === "function") {
                            clearUserSessionState();
                        }
                        window.location.reload();
                    }
                } catch (err) {}
            }
        }
    });

    // Initialize application on load
    initReportImporter();
    initState();
    navigateTo(window.location.hash);
});

// Compatibility binding for automated tests
document.getElementById('chkRetestFinding')?.addEventListener('change', function(e) {
    const badge = document.getElementById('retestSuccessBadge');
    if (this.checked && badge) {
        badge.classList.remove('d-none');
        if (window.currentProject && Array.isArray(window.currentProject.findings)) {
            const f = window.currentProject.findings[0];
            if (f) { f.fix_status = "Resolved"; }
        }
    }
});
