/**
 * API service layer — communicates with the FastAPI backend.
 */

const BASE_URL = 'http://localhost:8000'

/**
 * Upload a file and run the vulnerability scan.
 * @param {File} file - The file to scan
 * @param {function} onProgress - Optional progress callback (0-100)
 * @returns {Promise<object>} ScanResponse
 */
export async function scanFile(files, onProgress) {
    const formData = new FormData()
    // files can be a single File or an array of Files
    const fileList = Array.isArray(files) ? files : [files]

    fileList.forEach(file => {
        formData.append('files', file)
    })

    const response = await fetch(`${BASE_URL}/api/scan`, {
        method: 'POST',
        body: formData,
    })

    if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
        throw new Error(error.detail || `HTTP ${response.status}`)
    }

    return response.json()
}

/**
 * Health check
 */
export async function healthCheck() {
    const response = await fetch(`${BASE_URL}/health`)
    return response.json()
}

/**
 * Upload files and run vulnerability scan with streaming progress.
 * @param {File|File[]} files - Files to scan
 * @param {function} onEvent - Callback for progress events
 * @returns {Promise<object>} Final aggregated result structure
 */
export async function scanFileStream(files, onEvent) {
    const formData = new FormData()
    const fileList = Array.isArray(files) ? files : [files]
    fileList.forEach(file => formData.append('files', file))

    const response = await fetch(`${BASE_URL}/api/scan/progress`, {
        method: 'POST',
        body: formData,
    })

    if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
        throw new Error(error.detail || `HTTP ${response.status}`)
    }

    const reader = response.body.getReader()
    const decoder = new TextDecoder()
    let buffer = ''
    const results = []

    // Read the stream
    while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() // Keep potentially incomplete line in buffer

        for (const line of lines) {
            if (!line.trim()) continue
            try {
                const event = JSON.parse(line)
                if (event.type === 'error') {
                    throw new Error(event.message || 'Stream error')
                }

                if (onEvent) onEvent(event)

                if (event.type === 'file_complete') {
                    // event contains scan_id, risk_score, filename.
                    // But we likely need the full scan result (findings etc) to display results?
                    // scan_manager logic currently just emits scan_id.
                    // This is a disconnect!
                    // I need scan_manager to include full result in file_complete event!
                    // Or I need to fetch the result separately?
                    // Better: include full result in event.
                    results.push(event)
                }
            } catch (e) {
                console.warn("Failed to parse stream line", line, e)
                if (e.message !== 'Stream error') {
                    // ignore parse errors
                } else {
                    throw e
                }
            }
        }
    }

    // Construct final result manually since the backend doesn't return one big JSON
    // We need to re-create the structure that handleScan expects.
    // However, `file_complete` event in scan_manager currently ONLY has metadata.
    // I MUST UPDATE scan_manager.py to include the full `ScanResponse` dump in the event.

    // But first let's finish this file update.
    return {
        files: results.map(r => r.result), // Assume event.result contains the ScanResponse
        overall: {
            risk_score: Math.max(0, ...results.map(r => r.result?.risk_score || 0)),
            // Re-calculate basic overall stats or trust backend to send a summary event?
            // Backend sends simple events.
            // I should update scan_manager to send full result.
            total_files: results.length,
            risk_level: 'Calculated Frontend',
            processed_at: new Date().toISOString()
        }
    }
}
