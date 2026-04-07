import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { Layout, Menu, theme } from 'antd'
import { ProjectOutlined, ScanOutlined, HomeOutlined } from '@ant-design/icons'
import type { MenuProps } from 'antd'

const { Header, Sider, Content } = Layout

type MenuItem = Required<MenuProps>['items'][number]

function getItem(
  label: string,
  key: string,
  icon?: React.ReactNode,
  children?: MenuItem[],
): MenuItem {
  return {
    key,
    icon,
    children,
    label,
  } as MenuItem
}

const items: MenuItem[] = [
  getItem('首页', '/', <HomeOutlined />),
  getItem('项目管理', '/projects', <ProjectOutlined />),
  getItem('扫描管理', '/scans', <ScanOutlined />),
]

export default function AppLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const {
    token: { colorBgContainer, borderRadiusLG },
  } = theme.useToken()

  const handleMenuClick: MenuProps['onClick'] = (e) => {
    if (e.key !== '/') {
      navigate(e.key)
    }
  }

  // 根据当前路径确定选中的菜单项
  const getSelectedKey = () => {
    if (location.pathname.startsWith('/projects')) {
      return '/projects'
    }
    if (location.pathname.startsWith('/scans')) {
      return '/scans'
    }
    return '/'
  }

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        breakpoint="lg"
        collapsedWidth="0"
        style={{
          overflow: 'auto',
          height: '100vh',
          position: 'fixed',
          left: 0,
          top: 0,
          bottom: 0,
        }}
      >
        <div style={{
          height: 32,
          margin: 16,
          color: 'white',
          fontSize: 20,
          fontWeight: 'bold',
          textAlign: 'center',
        }}>
          DeepVuln
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[getSelectedKey()]}
          items={items}
          onClick={handleMenuClick}
        />
      </Sider>
      <Layout style={{ marginLeft: 200 }}>
        <Header style={{
          padding: 0,
          background: colorBgContainer,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          paddingRight: 24,
        }}>
          <div style={{ paddingLeft: 24, fontSize: 18, fontWeight: 500 }}>
            智能漏洞挖掘系统
          </div>
        </Header>
        <Content style={{
          margin: '24px 16px 0',
          overflow: 'initial',
        }}>
          <div
            style={{
              padding: 24,
              minHeight: 360,
              background: colorBgContainer,
              borderRadius: borderRadiusLG,
            }}
          >
            <Outlet />
          </div>
        </Content>
      </Layout>
    </Layout>
  )
}
