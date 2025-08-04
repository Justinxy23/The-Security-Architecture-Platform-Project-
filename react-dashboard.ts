import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  LinearProgress,
  IconButton,
  Chip,
  Alert,
  Button,
  useTheme,
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  AppBar,
  Toolbar
} from '@mui/material';
import {
  Shield,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  CloudOff,
  Lock,
  Scan,
  BarChart,
  Settings,
  Notifications,
  Menu as MenuIcon,
  Assessment,
  Security,
  BugReport,
  Policy
} from '@mui/icons-material';
import { Line, Doughnut, Bar } from 'react-chartjs-2';
import { 
  Chart as ChartJS, 
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  BarElement
} from 'chart.js';
import { useWebSocket } from '../hooks/useWebSocket';
import { SecurityPosture, Alert as SecurityAlert } from '../types/security';
import VulnerabilityScanner from './VulnerabilityScanner';
import ComplianceManager from './ComplianceManager';
import ThreatMap from './ThreatMap';

// Register ChartJS components
ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

interface DashboardProps {
  user: {
    name: string;
    role: string;
    email: string;
  };
}

const Dashboard: React.FC<DashboardProps> = ({ user }) => {
  const theme = useTheme();
  const [drawerOpen, setDrawerOpen] = useState(true);
  const [securityPosture, setSecurityPosture] = useState<SecurityPosture | null>(null);
  const [activeAlerts, setActiveAlerts] = useState<SecurityAlert[]>([]);
  const [selectedView, setSelectedView] = useState<string>('overview');
  const [loading, setLoading] = useState(true);

  // WebSocket connection for real-time updates
  const { data: wsData, isConnected } = useWebSocket('ws://localhost:8000/ws/security-feed');

  useEffect(() => {
    fetchSecurityData();
    const interval = setInterval(fetchSecurityData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (wsData) {
      // Update real-time metrics from WebSocket
      console.log('Real-time update:', wsData);
    }
  }, [wsData]);

  const fetchSecurityData = async () => {
    try {
      const [postureRes, alertsRes] = await Promise.all([
        fetch('/api/v1/security-posture', {
          headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        }),
        fetch('/api/v1/alerts/active?limit=10', {
          headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
        })
      ]);

      const postureData = await postureRes.json();
      const alertsData = await alertsRes.json();

      setSecurityPosture(postureData);
      setActiveAlerts(alertsData.alerts);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch security data:', error);
      setLoading(false);
    }
  };

  const triggerScan = async () => {
    try {
      const response = await fetch('/api/v1/scan/trigger', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          scan_type: 'full',
          targets: ['all']
        })
      });
      
      if (response.ok) {
        const data = await response.json();
        console.log('Scan initiated:', data);
      }
    } catch (error) {
      console.error('Failed to trigger scan:', error);
    }
  };

  const navigationItems = [
    { id: 'overview', label: 'Security Overview', icon: <Shield /> },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: <BugReport /> },
    { id: 'compliance', label: 'Compliance', icon: <Policy /> },
    { id: 'threats', label: 'Threat Detection', icon: <Security /> },
    { id: 'iam', label: 'Identity & Access', icon: <Lock /> },
    { id: 'reports', label: 'Reports', icon: <Assessment /> }
  ];

  const getSecurityScoreColor = (score: number) => {
    if (score >= 90) return theme.palette.success.main;
    if (score >= 70) return theme.palette.warning.main;
    return theme.palette.error.main;
  };

  const vulnerabilityChartData = {
    labels: ['Critical', 'High', 'Medium', 'Low'],
    datasets: [{
      data: [
        securityPosture?.vulnerabilities.critical || 0,
        securityPosture?.vulnerabilities.high || 0,
        securityPosture?.vulnerabilities.medium || 0,
        securityPosture?.vulnerabilities.low || 0
      ],
      backgroundColor: [
        theme.palette.error.main,
        theme.palette.warning.main,
        theme.palette.info.main,
        theme.palette.success.main
      ]
    }]
  };

  const threatTrendData = {
    labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
    datasets: [{
      label: 'Threats Detected',
      data: [65, 78, 90, 142, 156, 121, 98],
      borderColor: theme.palette.primary.main,
      backgroundColor: theme.palette.primary.light,
      tension: 0.4
    }]
  };

  const complianceData = {
    labels: ['CIS Benchmark', 'NIST Framework', 'ISO 27001'],
    datasets: [{
      label: 'Compliance Score',
      data: [
        securityPosture?.compliance.cis_benchmark || 0,
        securityPosture?.compliance.nist_framework || 0,
        securityPosture?.compliance.iso_27001 || 0
      ],
      backgroundColor: theme.palette.primary.main
    }]
  };

  const renderMainContent = () => {
    switch (selectedView) {
      case 'vulnerabilities':
        return <VulnerabilityScanner />;
      case 'compliance':
        return <ComplianceManager />;
      case 'threats':
        return <ThreatMap />;
      case 'overview':
      default:
        return (
          <Grid container spacing={3}>
            {/* Security Score Card */}
            <Grid item xs={12} md={3}>
              <Card elevation={3}>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between">
                    <Typography variant="h6" color="textSecondary">
                      Security Score
                    </Typography>
                    <Shield style={{ color: getSecurityScoreColor(securityPosture?.overall_score || 0) }} />
                  </Box>
                  <Typography variant="h2" style={{ 
                    color: getSecurityScoreColor(securityPosture?.overall_score || 0),
                    fontWeight: 'bold' 
                  }}>
                    {securityPosture?.overall_score || 0}
                  </Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={securityPosture?.overall_score || 0} 
                    style={{ marginTop: 10 }}
                    color={securityPosture?.overall_score >= 90 ? 'success' : 'warning'}
                  />
                </CardContent>
              </Card>
            </Grid>

            {/* Threat Activity */}
            <Grid item xs={12} md={3}>
              <Card elevation={3}>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between">
                    <Typography variant="h6" color="textSecondary">
                      24h Threats
                    </Typography>
                    <AlertTriangle color="warning" />
                  </Box>
                  <Typography variant="h3">
                    {securityPosture?.threats_detected.last_24h || 0}
                  </Typography>
                  <Box display="flex" gap={1} mt={1}>
                    <Chip 
                      label={`${securityPosture?.threats_detected.blocked || 0} Blocked`} 
                      color="success" 
                      size="small" 
                    />
                    <Chip 
                      label={`${securityPosture?.threats_detected.investigating || 0} Active`} 
                      color="warning" 
                      size="small" 
                    />
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Assets */}
            <Grid item xs={12} md={3}>
              <Card elevation={3}>
                <CardContent>
                  <Box display="flex" alignItems="center" justifyContent="space-between">
                    <Typography variant="h6" color="textSecondary">
                      Protected Assets
                    </Typography>
                    <CheckCircle color="success" />
                  </Box>
                  <Typography variant="h3">
                    {securityPosture?.assets.monitored || 0}
                  </Typography>
                  <Typography variant="body2" color="textSecondary">
                    of {securityPosture?.assets.total || 0} total assets
                  </Typography>
                  <LinearProgress 
                    variant="determinate" 
                    value={(securityPosture?.assets.monitored / securityPosture?.assets.total) * 100 || 0} 
                    style={{ marginTop: 10 }}
                  />
                </CardContent>
              </Card>
            </Grid>

            {/* Quick Actions */}
            <Grid item xs={12} md={3}>
              <Card elevation={3}>
                <CardContent>
                  <Typography variant="h6" color="textSecondary" gutterBottom>
                    Quick Actions
                  </Typography>
                  <Box display="flex" flexDirection="column" gap={1}>
                    <Button 
                      variant="contained" 
                      startIcon={<Scan />}
                      onClick={triggerScan}
                      fullWidth
                    >
                      Run Security Scan
                    </Button>
                    <Button 
                      variant="outlined" 
                      startIcon={<BarChart />}
                      fullWidth
                    >
                      Generate Report
                    </Button>
                  </Box>
                </CardContent>
              </Card>
            </Grid>

            {/* Vulnerability Distribution */}
            <Grid item xs={12} md={4}>
              <Paper elevation={3} sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Vulnerability Distribution
                </Typography>
                <Box height={250}>
                  <Doughnut 
                    data={vulnerabilityChartData} 
                    options={{ 
                      maintainAspectRatio: false,
                      plugins: {
                        legend: {
                          position: 'bottom'
                        }
                      }
                    }} 
                  />
                </Box>
              </Paper>
            </Grid>

            {/* Threat Trends */}
            <Grid item xs={12} md={4}>
              <Paper elevation={3} sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Threat Trends (7 Days)
                </Typography>
                <Box height={250}>
                  <Line 
                    data={threatTrendData} 
                    options={{ 
                      maintainAspectRatio: false,
                      plugins: {
                        legend: {
                          display: false
                        }
                      }
                    }} 
                  />
                </Box>
              </Paper>
            </Grid>

            {/* Compliance Scores */}
            <Grid item xs={12} md={4}>
              <Paper elevation={3} sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Compliance Scores
                </Typography>
                <Box height={250}>
                  <Bar 
                    data={complianceData} 
                    options={{ 
                      maintainAspectRatio: false,
                      plugins: {
                        legend: {
                          display: false
                        }
                      },
                      scales: {
                        y: {
                          max: 100
                        }
                      }
                    }} 
                  />
                </Box>
              </Paper>
            </Grid>

            {/* Active Alerts */}
            <Grid item xs={12}>
              <Paper elevation={3} sx={{ p: 3 }}>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                  <Typography variant="h6">
                    Active Security Alerts
                  </Typography>
                  <Chip 
                    label={isConnected ? 'Live' : 'Offline'} 
                    color={isConnected ? 'success' : 'error'}
                    icon={isConnected ? <CheckCircle /> : <CloudOff />}
                    size="small"
                  />
                </Box>
                {activeAlerts.length > 0 ? (
                  activeAlerts.map((alert, index) => (
                    <Alert 
                      key={index} 
                      severity={alert.severity}
                      sx={{ mb: 1 }}
                      action={
                        <Button color="inherit" size="small">
                          INVESTIGATE
                        </Button>
                      }
                    >
                      <strong>{alert.title}</strong> - {alert.description}
                    </Alert>
                  ))
                ) : (
                  <Typography color="textSecondary">
                    No active alerts at this time
                  </Typography>
                )}
              </Paper>
            </Grid>

            {/* Recommendations */}
            <Grid item xs={12}>
              <Paper elevation={3} sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Security Recommendations
                </Typography>
                {securityPosture?.recommendations.map((rec, index) => (
                  <Alert 
                    key={index}
                    severity={rec.priority === 'high' ? 'error' : 'warning'}
                    sx={{ mb: 2 }}
                  >
                    <strong>{rec.title}</strong>
                    <Typography variant="body2">{rec.description}</Typography>
                  </Alert>
                ))}
              </Paper>
            </Grid>
          </Grid>
        );
    }
  };

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh', backgroundColor: '#f5f5f5' }}>
      {/* App Bar */}
      <AppBar position="fixed" sx={{ zIndex: theme.zIndex.drawer + 1 }}>
        <Toolbar>
          <IconButton
            color="inherit"
            edge="start"
            onClick={() => setDrawerOpen(!drawerOpen)}
            sx={{ mr: 2 }}
          >
            <MenuIcon />
          </IconButton>
          <Shield sx={{ mr: 2 }} />
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            SecureArch Platform
          </Typography>
          <Typography variant="body2" sx={{ mr: 2 }}>
            {user.name} ({user.role})
          </Typography>
          <IconButton color="inherit">
            <Notifications />
          </IconButton>
          <IconButton color="inherit">
            <Settings />
          </IconButton>
        </Toolbar>
      </AppBar>

      {/* Side Navigation */}
      <Drawer
        variant="persistent"
        anchor="left"
        open={drawerOpen}
        sx={{
          width: drawerOpen ? 240 : 0,
          flexShrink: 0,
          '& .MuiDrawer-paper': {
            width: 240,
            boxSizing: 'border-box',
            top: 64
          },
        }}
      >
        <List>
          {navigationItems.map((item) => (
            <ListItem 
              button 
              key={item.id}
              selected={selectedView === item.id}
              onClick={() => setSelectedView(item.id)}
            >
              <ListItemIcon>{item.icon}</ListItemIcon>
              <ListItemText primary={item.label} />
            </ListItem>
          ))}
        </List>
        <Divider />
      </Drawer>

      {/* Main Content */}
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: 3,
          mt: 8,
          ml: drawerOpen ? '240px' : 0,
          transition: theme.transitions.create(['margin'], {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.leavingScreen,
          }),
        }}
      >
        {loading ? (
          <Box display="flex" justifyContent="center" alignItems="center" height="50vh">
            <LinearProgress style={{ width: '50%' }} />
          </Box>
        ) : (
          renderMainContent()
        )}
      </Box>
    </Box>
  );
};

export default Dashboard;