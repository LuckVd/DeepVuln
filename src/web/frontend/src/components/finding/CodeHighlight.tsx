import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter'
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism'

interface CodeHighlightProps {
  code: string
  language?: string
  highlightLine?: number
  startLine?: number
}

/**
 * 代码高亮组件
 * 支持多语言语法高亮、行号显示、指定行高亮
 */
export default function CodeHighlight({
  code,
  language = 'python',
  highlightLine,
  startLine = 1,
}: CodeHighlightProps) {
  // 语言映射（从常见扩展名到 SyntaxHighlighter 支持的语言）
  const languageMap: Record<string, string> = {
    py: 'python',
    python: 'python',
    js: 'javascript',
    javascript: 'javascript',
    ts: 'typescript',
    typescript: 'typescript',
    jsx: 'jsx',
    tsx: 'tsx',
    java: 'java',
    go: 'go',
    c: 'c',
    cpp: 'cpp',
    'c++': 'cpp',
    cs: 'csharp',
    php: 'php',
    rb: 'ruby',
    rs: 'rust',
    sql: 'sql',
    sh: 'bash',
    shell: 'bash',
    bash: 'bash',
    yaml: 'yaml',
    yml: 'yaml',
    json: 'json',
    xml: 'xml',
    html: 'html',
    css: 'css',
  }

  const resolvedLanguage = languageMap[language.toLowerCase()] || language

  // 计算目标行号（相对于代码块的行）
  const targetLine = highlightLine && highlightLine >= startLine ? highlightLine - startLine + 1 : undefined

  // 自定义行样式
  const lineProps = (lineNumber: number) => {
    if (targetLine && lineNumber === targetLine) {
      return {
        style: {
          backgroundColor: 'rgba(255, 77, 79, 0.2)',
          display: 'block',
          margin: '0 -1rem',
          paddingLeft: '1rem',
        },
      }
    }
    return {}
  }

  return (
    <div className="code-highlight">
      <SyntaxHighlighter
        language={resolvedLanguage}
        style={vscDarkPlus}
        showLineNumbers
        startingLineNumber={startLine}
        wrapLines
        lineProps={lineProps}
        customStyle={{
          borderRadius: '6px',
          fontSize: '13px',
          maxHeight: '400px',
          overflow: 'auto',
        }}
      >
        {code || '// 无代码'}
      </SyntaxHighlighter>
    </div>
  )
}
