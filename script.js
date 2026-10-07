document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('urlInput');
    const btn = document.getElementById('analyzeBtn');
    const errorMsg = document.getElementById('errorMsg');
    const loadingState = document.getElementById('loadingState');
    const resultsContainer = document.getElementById('resultsContainer');
    
    const resPing = document.getElementById('resPing');
    const mediaLinks = document.getElementById('mediaLinks');

    // URL Validation Regex
    const isValidUrl = (urlString) => {
        try {
            new URL(urlString);
            return true;
        } catch (err) {
            return false;
        }
    };

    btn.addEventListener('click', async () => {
        const url = input.value.trim();

        // 1. Validation
        if (!isValidUrl(url)) {
            errorMsg.style.display = 'block';
            return;
        }
        errorMsg.style.display = 'none';

        // 2. UI State: Loading
        resultsContainer.style.display = 'none';
        loadingState.style.display = 'block';

        // 3. Simulate Analysis (Real implementation needs a backend server)
        await simulateAnalysis(url);
    });

    async function simulateAnalysis(url) {
        // Simulating network delay
        return new Promise(resolve => {
            setTimeout(() => {
                // Mock Data Generation
                const pingTime = Math.floor(Math.random() * 200) + 50;
                
                // Populate Data
                resPing.textContent = `${pingTime} ms`;
                
                // Generate Mock Media Links
                mediaLinks.innerHTML = `
                    <li><a href="${url}/video/promo.mp4" target="_blank"><i class="fa-solid fa-link"></i> promo.mp4</a></li>
                    <li><a href="${url}/assets/main-bg.jpg" target="_blank"><i class="fa-solid fa-image"></i> main-bg.jpg</a></li>
                    <li><a href="${url}/public/document.pdf" target="_blank"><i class="fa-solid fa-file-pdf"></i> document.pdf</a></li>
                `;

                // 4. UI State: Show Results
                loadingState.style.display = 'none';
                resultsContainer.style.display = 'grid';
                resolve();
            }, 2500); // 2.5 second fake loading
        });
    }

    // Allow pressing Enter to search
    input.addEventListener('keypress', function (e) {
        if (e.key === 'Enter') {
            btn.click();
        }
    });
});