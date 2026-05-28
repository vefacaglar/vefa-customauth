window.adminApp = function() {
    const basePath = window.location.pathname.replace(/\/$/, '');
    const apiBase = basePath + '/api/clients';
    const scopesApiBase = basePath + '/api/scopes';
    const sessionsApiBase = basePath + '/api/sessions';
    const tokensApiBase = basePath + '/api/refresh-tokens';
    const keysApiBase = basePath + '/api/signing-keys';
    const auditApiBase = basePath + '/api/audit-logs';

    return {
        // App State
        activeTab: 'clients',
        clients: [],
        scopes: [],
        sessions: [],
        refreshTokens: [],
        signingKeys: [],
        auditLogs: [],
        availableScopes: [
            { name: 'openid', description: 'Access user identifier.' },
            { name: 'profile', description: 'Access user profile details.' },
            { name: 'email', description: 'Access user email address.' },
            { name: 'offline_access', description: 'Allow background refresh token exchange.' }
        ],
        searchQuery: '',
        sessionSearch: '',
        tokenSearch: '',
        auditSearch: '',
        loading: false,
        configFormat: 'json',
        modalOpen: false,
        scopeModalOpen: false,
        selectedClientId: null,
        
        // Toast Notification State
        toast: {
            show: false,
            message: '',
            type: 'success'
        },

        // Client Form State
        form: {
            isEdit: false,
            clientId: '',
            displayName: '',
            redirectUrisRaw: '',
            postLogoutRedirectUrisRaw: '',
            allowedScopes: [],
            accessTokenLifetimeSeconds: 3600,
            refreshTokenLifetimeSeconds: 2592000,
            requirePkce: true,
            allowRefreshTokens: true
        },

        // Scope Form State
        scopeForm: {
            isEdit: false,
            name: '',
            displayName: '',
            description: '',
            required: false,
            emphasize: false
        },

        // Initialize App
        init() {
            this.loadClients();
            this.loadAvailableScopes();
        },

        // Fetch Clients from API
        async loadClients() {
            this.loading = true;
            try {
                const response = await fetch(`${apiBase}?page=1&pageSize=100`);
                if (!response.ok) throw new Error('Failed to retrieve clients list.');
                
                const data = await response.json();
                this.clients = data.items || [];
                
                // Set/Maintain active selection
                if (this.clients.length > 0) {
                    if (!this.selectedClientId || !this.clients.some(c => c.clientId === this.selectedClientId)) {
                        this.selectedClientId = this.clients[0].clientId;
                    }
                } else {
                    this.selectedClientId = null;
                }
            } catch (error) {
                this.showToast(error.message, 'danger');
            } finally {
                this.loading = false;
            }
        },

        // Filter clients in real-time
        filteredClients() {
            if (!this.searchQuery) return this.clients;
            const query = this.searchQuery.toLowerCase().trim();
            return this.clients.filter(c => 
                c.clientId.toLowerCase().includes(query) ||
                (c.displayName && c.displayName.toLowerCase().includes(query))
            );
        },

        // Modal Controls
        openCreateModal() {
            this.form = {
                isEdit: false,
                clientId: '',
                displayName: '',
                redirectUrisRaw: '',
                postLogoutRedirectUrisRaw: '',
                allowedScopes: ['openid', 'profile'],
                accessTokenLifetimeSeconds: 3600,
                refreshTokenLifetimeSeconds: 2592000,
                requirePkce: true,
                allowRefreshTokens: true
            };
            this.modalOpen = true;
        },

        openEditModal(client) {
            this.form = {
                isEdit: true,
                clientId: client.clientId,
                displayName: client.displayName || '',
                redirectUrisRaw: (client.redirectUris || []).join('\n'),
                postLogoutRedirectUrisRaw: (client.postLogoutRedirectUris || []).join('\n'),
                allowedScopes: [...(client.allowedScopes || [])],
                accessTokenLifetimeSeconds: client.accessTokenLifetimeSeconds,
                refreshTokenLifetimeSeconds: client.refreshTokenLifetimeSeconds,
                requirePkce: client.requirePkce,
                allowRefreshTokens: client.allowRefreshTokens
            };
            this.modalOpen = true;
        },

        closeModal() {
            this.modalOpen = false;
        },

        // Interactive Scope Picker Grid Toggles
        toggleScope(scopeName) {
            const idx = this.form.allowedScopes.indexOf(scopeName);
            if (idx > -1) {
                // Remove if not required OIDC scope
                if (scopeName === 'openid') return;
                this.form.allowedScopes.splice(idx, 1);
            } else {
                this.form.allowedScopes.push(scopeName);
            }
        },

        isScopeSelected(scopeName) {
            return this.form.allowedScopes.includes(scopeName);
        },

        // Submit Form
        async submitForm() {
            const isEdit = this.form.isEdit;
            const clientData = {
                clientId: this.form.clientId.trim(),
                displayName: this.form.displayName.trim(),
                redirectUris: this.form.redirectUrisRaw.split('\n').map(u => u.trim()).filter(u => u !== ''),
                postLogoutRedirectUris: this.form.postLogoutRedirectUrisRaw.split('\n').map(u => u.trim()).filter(u => u !== ''),
                allowedScopes: this.form.allowedScopes,
                accessTokenLifetimeSeconds: this.form.accessTokenLifetimeSeconds,
                refreshTokenLifetimeSeconds: this.form.refreshTokenLifetimeSeconds,
                requirePkce: this.form.requirePkce,
                allowRefreshTokens: this.form.allowRefreshTokens
            };

            try {
                const url = isEdit ? `${apiBase}/${encodeURIComponent(clientData.clientId)}` : apiBase;
                const method = isEdit ? 'PUT' : 'POST';

                const response = await fetch(url, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(clientData)
                });

                if (!response.ok) {
                    const errText = await response.text();
                    throw new Error(errText || 'Failed to save client details.');
                }

                this.closeModal();
                this.showToast(isEdit ? 'Client configuration updated.' : 'Client registered successfully.');
                await this.loadClients();
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        },

        // Delete Client
        async deleteClient(clientId) {
            if (!confirm(`Are you sure you want to delete client '${clientId}'?`)) {
                return;
            }

            try {
                const response = await fetch(`${apiBase}/${encodeURIComponent(clientId)}`, {
                    method: 'DELETE'
                });

                if (!response.ok) throw new Error('Failed to delete client.');

                this.showToast('Client deleted successfully.');
                await this.loadClients();
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        },

        // Live Code Previews Generators
        getActiveClientId() {
            if (this.modalOpen && this.form.clientId) return this.form.clientId;
            if (this.selectedClientId) return this.selectedClientId;
            if (this.clients.length > 0) return this.clients[0].clientId;
            return 'sample-webapp';
        },

        generateJsonPreview() {
            const clientId = this.getActiveClientId();
            const host = window.location.origin;
            return JSON.stringify({
                "Authentication": {
                    "Schemes": {
                        "Bearer": {
                            "Authority": host,
                            "ValidAudiences": [ clientId ],
                            "RequireHttpsMetadata": false
                        }
                    }
                }
            }, null, 2);
        },

        generateCsharpPreview() {
            const clientId = this.getActiveClientId();
            const host = window.location.origin;
            return `// ASP.NET Core API - JWT Bearer Configuration
builder.Services
    .AddAuthentication("Bearer")
    .AddJwtBearer(options =>
    {
        options.Authority = "${host}";
        options.Audience = "${clientId}";
        options.RequireHttpsMetadata = false;
    });`;
        },

        copyConfig() {
            const code = this.configFormat === 'json' ? this.generateJsonPreview() : this.generateCsharpPreview();
            navigator.clipboard.writeText(code)
                .then(() => this.showToast('Configuration copied to clipboard!'))
                .catch(() => this.showToast('Failed to copy configuration.', 'danger'));
        },

        // Utility: Toast control
        showToast(message, type = 'success') {
            this.toast.message = message;
            this.toast.type = type;
            this.toast.show = true;

            setTimeout(() => {
                this.toast.show = false;
            }, 3000);
        },

        // Utility: Lifetime formatter
        formatLifetime(sec) {
            if (sec < 60) return `${sec}s`;
            const min = Math.floor(sec / 60);
            if (min < 60) return `${min}m`;
            const hr = Math.floor(min / 60);
            if (hr < 24) return `${hr}h`;
            const day = Math.floor(hr / 24);
            return `${day}d`;
        },

        // Utility: Date formatter
        formatDate(dateStr) {
            if (!dateStr) return '-';
            const d = new Date(dateStr);
            return d.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
        },

        isRefreshTokenActive(token) {
            const now = new Date();
            return !token.revokedAt
                && !token.consumedAt
                && new Date(token.expiresAt) > now
                && new Date(token.absoluteExpiresAt) > now;
        },

        // Load available scopes for client form picker
        async loadAvailableScopes() {
            try {
                const response = await fetch(scopesApiBase);
                if (response.ok) {
                    const data = await response.json();
                    if (data && data.length > 0) {
                        this.availableScopes = data.map(s => ({ name: s.name, description: s.description || '' }));
                    }
                }
            } catch (e) {
                // Keep default scopes if API fails
            }
        },

        // Scope Management
        async loadScopes() {
            try {
                const response = await fetch(scopesApiBase);
                if (!response.ok) throw new Error('Failed to load scopes.');
                this.scopes = await response.json();
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        },

        openScopeModal(scope = null) {
            if (scope) {
                this.scopeForm = {
                    isEdit: true,
                    name: scope.name,
                    displayName: scope.displayName || '',
                    description: scope.description || '',
                    required: scope.required || false,
                    emphasize: scope.emphasize || false
                };
            } else {
                this.scopeForm = {
                    isEdit: false,
                    name: '',
                    displayName: '',
                    description: '',
                    required: false,
                    emphasize: false
                };
            }
            this.scopeModalOpen = true;
        },

        closeScopeModal() {
            this.scopeModalOpen = false;
        },

        async submitScopeForm() {
            const isEdit = this.scopeForm.isEdit;
            const scopeData = {
                name: this.scopeForm.name.trim(),
                displayName: this.scopeForm.displayName.trim(),
                description: this.scopeForm.description.trim(),
                required: this.scopeForm.required,
                emphasize: this.scopeForm.emphasize
            };

            try {
                const url = isEdit ? `${scopesApiBase}/${encodeURIComponent(scopeData.name)}` : scopesApiBase;
                const method = isEdit ? 'PUT' : 'POST';

                const response = await fetch(url, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(scopeData)
                });

                if (!response.ok) {
                    const errText = await response.text();
                    throw new Error(errText || 'Failed to save scope.');
                }

                this.closeScopeModal();
                this.showToast(isEdit ? 'Scope updated.' : 'Scope created.');
                await this.loadScopes();
                await this.loadAvailableScopes();
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        },

        async deleteScope(name) {
            if (!confirm(`Are you sure you want to delete scope '${name}'?`)) return;

            try {
                const response = await fetch(`${scopesApiBase}/${encodeURIComponent(name)}`, { method: 'DELETE' });
                if (!response.ok) throw new Error('Failed to delete scope.');
                this.showToast('Scope deleted.');
                await this.loadScopes();
                await this.loadAvailableScopes();
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        },

        // Session Management
        async loadSessions() {
            try {
                const params = new URLSearchParams({ page: '1', pageSize: '50' });
                if (this.sessionSearch) params.set('search', this.sessionSearch);
                const response = await fetch(`${sessionsApiBase}?${params}`);
                if (!response.ok) throw new Error('Failed to load sessions.');
                const data = await response.json();
                this.sessions = data.items || [];
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        },

        async revokeSession(sessionId) {
            if (!confirm('Are you sure you want to revoke this session?')) return;

            try {
                const response = await fetch(`${sessionsApiBase}/${sessionId}/revoke`, { method: 'POST' });
                if (!response.ok) throw new Error('Failed to revoke session.');
                this.showToast('Session revoked.');
                await this.loadSessions();
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        },

        // Refresh Token Management
        async loadRefreshTokens() {
            try {
                const params = new URLSearchParams({ page: '1', pageSize: '50' });
                if (this.tokenSearch) params.set('search', this.tokenSearch);
                const response = await fetch(`${tokensApiBase}?${params}`);
                if (!response.ok) throw new Error('Failed to load refresh tokens.');
                const data = await response.json();
                this.refreshTokens = data.items || [];
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        },

        async revokeRefreshToken(tokenId) {
            if (!confirm('Are you sure you want to revoke this refresh token?')) return;

            try {
                const response = await fetch(`${tokensApiBase}/${tokenId}/revoke`, { method: 'POST' });
                if (!response.ok) throw new Error('Failed to revoke refresh token.');
                this.showToast('Refresh token revoked.');
                await this.loadRefreshTokens();
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        },

        // Signing Key Management
        async loadSigningKeys() {
            try {
                const response = await fetch(keysApiBase);
                if (!response.ok) throw new Error('Failed to load signing keys.');
                this.signingKeys = await response.json();
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        },

        // Audit Log Management
        async loadAuditLogs() {
            try {
                const params = new URLSearchParams({ page: '1', pageSize: '50' });
                if (this.auditSearch) params.set('search', this.auditSearch);
                const response = await fetch(`${auditApiBase}?${params}`);
                if (!response.ok) throw new Error('Failed to load audit logs.');
                const data = await response.json();
                this.auditLogs = data.items || [];
            } catch (error) {
                this.showToast(error.message, 'danger');
            }
        }
    };
};
