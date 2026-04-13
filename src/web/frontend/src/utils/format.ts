/**
 * 时间格式化工具函数
 * 支持时区转换
 */

export type TimeZone = string

// 常用时区列表
export const TIMEZONES: { value: string; label: string; offset: string }[] = [
  { value: 'UTC', label: 'UTC (世界标准时间)', offset: 'UTC±0' },
  { value: 'Asia/Shanghai', label: 'Asia/Shanghai (中国标准时间)', offset: 'UTC+8' },
  { value: 'Asia/Tokyo', label: 'Asia/Tokyo (日本标准时间)', offset: 'UTC+9' },
  { value: 'Asia/Seoul', label: 'Asia/Seoul (韩国标准时间)', offset: 'UTC+9' },
  { value: 'Asia/Singapore', label: 'Asia/Singapore (新加坡时间)', offset: 'UTC+8' },
  { value: 'Asia/Hong_Kong', label: 'Asia/Hong_Kong (香港时间)', offset: 'UTC+8' },
  { value: 'Asia/Taipei', label: 'Asia/Taipei (台北时间)', offset: 'UTC+8' },
  { value: 'America/New_York', label: 'America/New_York (美东时间)', offset: 'UTC-5' },
  { value: 'America/Los_Angeles', label: 'America/Los_Angeles (美西时间)', offset: 'UTC-8' },
  { value: 'Europe/London', label: 'Europe/London (格林威治时间)', offset: 'UTC+0' },
  { value: 'Europe/Paris', label: 'Europe/Paris (中欧时间)', offset: 'UTC+1' },
  { value: 'Europe/Berlin', label: 'Europe/Berlin (德国时间)', offset: 'UTC+1' },
  { value: 'Australia/Sydney', label: 'Australia/Sydney (澳洲东部时间)', offset: 'UTC+10' },
]

let currentTimezone: TimeZone = 'Asia/Shanghai'

/**
 * 设置当前时区
 */
export function setTimezone(timezone: TimeZone): void {
  currentTimezone = timezone
}

/**
 * 获取当前时区
 */
export function getTimezone(): TimeZone {
  return currentTimezone
}

/**
 * 格式化日期时间为本地字符串
 * @param isoString ISO 8601 格式的日期时间字符串
 * @param withSeconds 是否包含秒
 * @returns 格式化后的日期时间字符串
 */
export function formatDateTime(isoString: string | Date | null | undefined, withSeconds = true): string {
  if (!isoString) return '--'
  
  const date = typeof isoString === 'string' ? new Date(isoString) : isoString
  
  // 检查日期是否有效
  if (isNaN(date.getTime())) return '--'
  
  const options: Intl.DateTimeFormatOptions = {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: currentTimezone,
  }
  
  if (withSeconds) {
    options.second = '2-digit'
  }
  
  return date.toLocaleString('zh-CN', options)
}

/**
 * 格式化日期为短格式
 * @param isoString ISO 8601 格式的日期字符串
 * @returns 格式化后的日期字符串 (YYYY/MM/DD)
 */
export function formatDate(isoString: string | Date | null | undefined): string {
  if (!isoString) return '--'
  
  const date = typeof isoString === 'string' ? new Date(isoString) : isoString
  
  if (isNaN(date.getTime())) return '--'
  
  return date.toLocaleDateString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    timeZone: currentTimezone,
  })
}

/**
 * 格式化时间为短格式
 * @param isoString ISO 8601 格式的日期时间字符串
 * @returns 格式化后的时间字符串 (HH:mm:ss)
 */
export function formatTime(isoString: string | Date | null | undefined): string {
  if (!isoString) return '--'
  
  const date = typeof isoString === 'string' ? new Date(isoString) : isoString
  
  if (isNaN(date.getTime())) return '--'
  
  return date.toLocaleTimeString('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    timeZone: currentTimezone,
  })
}

/**
 * 格式化持续时间（秒）为可读字符串
 * @param seconds 持续时间（秒）
 * @returns 格式化后的持续时间字符串
 */
export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '--'
  
  if (seconds < 60) {
    return `${Math.round(seconds)}秒`
  } else if (seconds < 3600) {
    return `${Math.round(seconds / 60)}分钟`
  } else if (seconds < 86400) {
    const hours = Math.floor(seconds / 3600)
    const minutes = Math.round((seconds % 3600) / 60)
    return minutes > 0 ? `${hours}小时${minutes}分钟` : `${hours}小时`
  } else {
    const days = Math.floor(seconds / 86400)
    const hours = Math.round((seconds % 86400) / 3600)
    return hours > 0 ? `${days}天${hours}小时` : `${days}天`
  }
}

/**
 * 获取时区偏移量字符串
 * @param timezone 时区标识
 * @returns 时区偏移量字符串 (如 UTC+8)
 */
export function getTimezoneOffset(timezone: string): string {
  const tz = TIMEZONES.find(t => t.value === timezone)
  return tz?.offset || 'UTC'
}
