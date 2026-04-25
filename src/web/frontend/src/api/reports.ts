import client from './client'

/**
 * 报告导出 API
 */
export const reportsApi = {
  /**
   * 导出 JSON 格式报告
   */
  async exportJson(scanId: number): Promise<any> {
    const response = await client.get(`/scans/${scanId}/report`)
    return response.data
  },

  /**
   * 导出 CSV 格式报告
   */
  async exportCsv(scanId: number): Promise<Blob> {
    const response = await client.get(`/scans/${scanId}/report/csv`, {
      responseType: 'blob',
    })
    return response.data
  },

  /**
   * 导出 PDF 格式报告
   */
  async exportPdf(scanId: number): Promise<Blob> {
    const response = await client.get(`/scans/${scanId}/report/pdf`, {
      responseType: 'blob',
    })
    return response.data
  },

  /**
   * 导出 HTML 格式报告
   */
  async exportHtml(scanId: number): Promise<Blob> {
    const response = await client.get(`/scans/${scanId}/report/pdf`, {
      responseType: 'blob',
    })
    return response.data
  },

  /**
   * 下载文件
   */
  downloadBlob(blob: Blob, filename: string) {
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    window.URL.revokeObjectURL(url)
    document.body.removeChild(a)
  },
}
