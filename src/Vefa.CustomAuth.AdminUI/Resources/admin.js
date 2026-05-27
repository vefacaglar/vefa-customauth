window.adminApp = function() {
    const apiBase = window.location.pathname.replace(/\/$/, '') + '/api/clients';

    return {
        // App State
        clients: [],
        availableScopes: [
            { name: 'openid', description: 'Access user identifier.' },
            { name: 'profile', description: 'Access user profile details.' },
            { name: 'email', description: 'Access user email address.' },
            { name: 'offline_access', description: 'Allow background refresh token exchange.' }
        ],
        searchQuery: '',
        loading: false,
        configFormat: 'json',
        modalOpen: false,
        
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

        // Initialize App
        init() {
            this.loadClients();
        },

        // Fetch Clients from API
        async loadClients() {
            this.loading = true;
            try {
                const response = await fetch(`${apiBase}?page=1&pageSize=100`);
                if (!response.ok) throw new Error('Failed to retrieve clients list.');
                
                const data = await response.json();
                this.clients = data.items || [];
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
            if (this.form.clientId) return this.form.clientId;
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
        }
    };
};
