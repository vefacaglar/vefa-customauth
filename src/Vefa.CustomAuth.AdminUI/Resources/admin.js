document.addEventListener('DOMContentLoaded', () => {
    // API endpoint root is relative to the current path prefix
    const apiBase = window.location.pathname.replace(/\/$/, '') + '/api/clients';
    
    // DOM Elements
    const clientsGrid = document.getElementById('clients-grid');
    const loadingSpinner = document.getElementById('clients-loading');
    const emptyState = document.getElementById('clients-empty');
    const clientModal = document.getElementById('client-modal');
    const clientForm = document.getElementById('client-form');
    
    const btnCreateClient = document.getElementById('btn-create-client');
    const btnCreateClientEmpty = document.getElementById('btn-create-client-empty');
    const btnCancel = document.getElementById('btn-cancel');
    const modalClose = document.getElementById('modal-close');
    const modalTitle = document.getElementById('modal-title');
    const toast = document.getElementById('toast');
    
    // Form Inputs
    const inputIsEdit = document.getElementById('form-is-edit');
    const inputClientId = document.getElementById('client-id');
    const inputDisplayName = document.getElementById('display-name');
    const inputRedirectUris = document.getElementById('redirect-uris');
    const inputPostLogoutRedirectUris = document.getElementById('post-logout-redirect-uris');
    const inputAllowedScopes = document.getElementById('allowed-scopes');
    const inputAccessTokenLifetime = document.getElementById('access-token-lifetime');
    const inputRefreshTokenLifetime = document.getElementById('refresh-token-lifetime');
    const inputRequirePkce = document.getElementById('require-pkce');
    const inputAllowRefreshTokens = document.getElementById('allow-refresh-tokens');

    // Fetch and render clients
    async function loadClients() {
        showLoading(true);
        try {
            // Requesting page=1, pageSize=100 for admin view
            const response = await fetch(`${apiBase}?page=1&pageSize=100`);
            if (!response.ok) throw new Error('Failed to retrieve clients.');
            
            const data = await response.json();
            renderClients(data.items || []);
        } catch (error) {
            showToast(error.message, 'danger');
        } finally {
            showLoading(false);
        }
    }

    function renderClients(clients) {
        clientsGrid.innerHTML = '';
        
        if (clients.length === 0) {
            clientsGrid.classList.add('hidden');
            emptyState.classList.remove('hidden');
            return;
        }

        emptyState.classList.add('hidden');
        clientsGrid.classList.remove('hidden');

        clients.forEach(client => {
            const card = document.createElement('div');
            card.className = 'client-card';
            
            const redirectUrisHtml = client.redirectUris && client.redirectUris.length > 0
                ? client.redirectUris.map(u => `<div>${escapeHtml(u)}</div>`).join('')
                : '<div class="text-muted">None</div>';

            const scopesHtml = client.allowedScopes && client.allowedScopes.length > 0
                ? client.allowedScopes.map(s => `<span class="scope-pill">${escapeHtml(s)}</span>`).join('')
                : '<span class="text-muted">None</span>';

            card.innerHTML = `
                <div class="card-header">
                    <div class="client-info">
                        <h3>${escapeHtml(client.displayName || 'Unnamed Client')}</h3>
                        <span class="client-id">${escapeHtml(client.clientId)}</span>
                    </div>
                </div>
                <div class="card-body">
                    <div class="info-item">
                        <span class="info-label">Redirect URIs</span>
                        <div class="info-value">${redirectUrisHtml}</div>
                    </div>
                    <div class="info-item">
                        <span class="info-label">Allowed Scopes</span>
                        <div class="scope-pills">${scopesHtml}</div>
                    </div>
                    <div class="form-row" style="margin-top: 1rem;">
                        <div class="info-item">
                            <span class="info-label">Token Lifetime</span>
                            <span class="info-value">${client.accessTokenLifetimeSeconds}s (Access)</span>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Security</span>
                            <span class="info-value">
                                ${client.requirePkce ? '🔒 PKCE Required' : '🔓 PKCE Optional'}<br/>
                                ${client.allowRefreshTokens ? '🔄 Refresh Allowed' : '🚫 Refresh Disabled'}
                            </span>
                        </div>
                    </div>
                </div>
                <div class="card-footer">
                    <button class="btn btn-secondary btn-edit" data-id="${escapeHtml(client.clientId)}">Edit</button>
                    <button class="btn btn-danger btn-delete" data-id="${escapeHtml(client.clientId)}">Delete</button>
                </div>
            `;

            // Attach listeners to buttons inside this card
            card.querySelector('.btn-edit').addEventListener('click', () => openEditModal(client));
            card.querySelector('.btn-delete').addEventListener('click', () => deleteClient(client.clientId));

            clientsGrid.appendChild(card);
        });
    }

    // Modal Control
    function showModal(show, isEdit = false) {
        if (show) {
            clientForm.reset();
            inputIsEdit.value = isEdit ? 'true' : 'false';
            inputClientId.disabled = isEdit;
            modalTitle.textContent = isEdit ? 'Edit Client Configuration' : 'Register Client Application';
            clientModal.classList.remove('hidden');
        } else {
            clientModal.classList.add('hidden');
        }
    }

    function openEditModal(client) {
        showModal(true, true);
        inputClientId.value = client.clientId;
        inputDisplayName.value = client.displayName || '';
        inputRedirectUris.value = (client.redirectUris || []).join('\n');
        inputPostLogoutRedirectUris.value = (client.postLogoutRedirectUris || []).join('\n');
        inputAllowedScopes.value = (client.allowedScopes || []).join(' ');
        inputAccessTokenLifetime.value = client.accessTokenLifetimeSeconds;
        inputRefreshTokenLifetime.value = client.refreshTokenLifetimeSeconds;
        inputRequirePkce.checked = client.requirePkce;
        inputAllowRefreshTokens.checked = client.allowRefreshTokens;
    }

    // Form Submission (Create or Edit)
    clientForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const isEdit = inputIsEdit.value === 'true';
        
        const clientData = {
            clientId: inputClientId.value.trim(),
            displayName: inputDisplayName.value.trim(),
            redirectUris: inputRedirectUris.value.split('\n').map(u => u.trim()).filter(u => u !== ''),
            postLogoutRedirectUris: inputPostLogoutRedirectUris.value.split('\n').map(u => u.trim()).filter(u => u !== ''),
            allowedScopes: inputAllowedScopes.value.split(' ').map(s => s.trim()).filter(s => s !== ''),
            accessTokenLifetimeSeconds: parseInt(inputAccessTokenLifetime.value, 10),
            refreshTokenLifetimeSeconds: parseInt(inputRefreshTokenLifetime.value, 10),
            requirePkce: inputRequirePkce.checked,
            allowRefreshTokens: inputAllowRefreshTokens.checked
        };

        try {
            const method = isEdit ? 'PUT' : 'POST';
            const url = isEdit ? `${apiBase}/${encodeURIComponent(clientData.clientId)}` : apiBase;
            
            const response = await fetch(url, {
                method: method,
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(clientData)
            });

            if (!response.ok) {
                const errText = await response.text();
                throw new Error(errText || 'Failed to save client.');
            }

            showModal(false);
            showToast(isEdit ? 'Client updated successfully.' : 'Client registered successfully.');
            await loadClients();
        } catch (error) {
            showToast(error.message, 'danger');
        }
    });

    // Delete Client
    async function deleteClient(clientId) {
        if (!confirm(`Are you sure you want to delete client '${clientId}'? This action cannot be undone.`)) {
            return;
        }

        try {
            const response = await fetch(`${apiBase}/${encodeURIComponent(clientId)}`, {
                method: 'DELETE'
            });

            if (!response.ok) throw new Error('Failed to delete client.');

            showToast('Client deleted successfully.');
            await loadClients();
        } catch (error) {
            showToast(error.message, 'danger');
        }
    }

    // Helpers
    function showLoading(show) {
        if (show) {
            loadingSpinner.classList.remove('hidden');
            clientsGrid.classList.add('hidden');
            emptyState.classList.add('hidden');
        } else {
            loadingSpinner.classList.add('hidden');
        }
    }

    function showToast(message, type = 'success') {
        toast.textContent = message;
        toast.style.borderLeftColor = type === 'danger' ? 'var(--danger-color)' : 'var(--primary-color)';
        toast.classList.remove('hidden');
        
        setTimeout(() => {
            toast.classList.add('hidden');
        }, 4000);
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // Event Listeners
    btnCreateClient.addEventListener('click', () => showModal(true, false));
    btnCreateClientEmpty.addEventListener('click', () => showModal(true, false));
    btnCancel.addEventListener('click', () => showModal(false));
    modalClose.addEventListener('click', () => showModal(false));

    // Initial Load
    loadClients();
});
