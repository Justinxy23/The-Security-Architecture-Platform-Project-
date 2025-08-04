import SwiftUI
import Charts
import LocalAuthentication
import UserNotifications
import Combine

// MARK: - Main App View
struct ContentView: View {
    @StateObject private var viewModel = SecurityViewModel()
    @State private var selectedTab = 0
    @State private var showingSettings = false
    @State private var isAuthenticated = false
    
    var body: some View {
        Group {
            if isAuthenticated {
                authenticatedView
            } else {
                AuthenticationView(isAuthenticated: $isAuthenticated)
            }
        }
        .onAppear {
            viewModel.requestNotificationPermission()
            authenticateUser()
        }
    }
    
    var authenticatedView: some View {
        TabView(selection: $selectedTab) {
            DashboardView(viewModel: viewModel)
                .tabItem {
                    Label("Dashboard", systemImage: "shield.fill")
                }
                .tag(0)
            
            AlertsView(viewModel: viewModel)
                .tabItem {
                    Label("Alerts", systemImage: "exclamationmark.triangle.fill")
                }
                .tag(1)
                .badge(viewModel.activeAlerts.count)
            
            VulnerabilitiesView(viewModel: viewModel)
                .tabItem {
                    Label("Vulnerabilities", systemImage: "ant.fill")
                }
                .tag(2)
            
            ComplianceView(viewModel: viewModel)
                .tabItem {
                    Label("Compliance", systemImage: "checkmark.seal.fill")
                }
                .tag(3)
            
            ActionsView(viewModel: viewModel)
                .tabItem {
                    Label("Actions", systemImage: "play.circle.fill")
                }
                .tag(4)
        }
        .accentColor(.blue)
        .sheet(isPresented: $showingSettings) {
            SettingsView()
        }
    }
    
    func authenticateUser() {
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, 
                                 localizedReason: "Access SecureArch Platform") { success, _ in
                DispatchQueue.main.async {
                    isAuthenticated = success
                }
            }
        } else {
            // Fallback to passcode
            isAuthenticated = true
        }
    }
}

// MARK: - Authentication View
struct AuthenticationView: View {
    @Binding var isAuthenticated: Bool
    @State private var showingError = false
    
    var body: some View {
        VStack(spacing: 40) {
            Spacer()
            
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 80))
                .foregroundStyle(.blue.gradient)
            
            VStack(spacing: 8) {
                Text("SecureArch Platform")
                    .font(.largeTitle)
                    .fontWeight(.bold)
                
                Text("Security Architecture Management")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
            
            Button(action: authenticate) {
                Label("Authenticate with Face ID", systemImage: "faceid")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(12)
            }
            .padding(.horizontal, 40)
            
            Spacer()
            
            Text("By Justin Weaver")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .alert("Authentication Failed", isPresented: $showingError) {
            Button("Try Again", action: authenticate)
        }
    }
    
    func authenticate() {
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                             localizedReason: "Access your security data") { success, _ in
            DispatchQueue.main.async {
                if success {
                    withAnimation {
                        isAuthenticated = true
                    }
                } else {
                    showingError = true
                }
            }
        }
    }
}

// MARK: - Dashboard View
struct DashboardView: View {
    @ObservedObject var viewModel: SecurityViewModel
    @State private var selectedTimeRange = TimeRange.day
    
    enum TimeRange: String, CaseIterable {
        case hour = "1H"
        case day = "24H"
        case week = "7D"
        case month = "30D"
    }
    
    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 20) {
                    // Security Score Card
                    SecurityScoreCard(score: viewModel.securityScore)
                        .padding(.horizontal)
                    
                    // Quick Stats
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 15) {
                        StatCard(
                            title: "Active Threats",
                            value: "\(viewModel.activeThreats)",
                            icon: "exclamationmark.shield.fill",
                            color: .red
                        )
                        
                        StatCard(
                            title: "Protected Assets",
                            value: "\(viewModel.protectedAssets)/\(viewModel.totalAssets)",
                            icon: "checkmark.shield.fill",
                            color: .green
                        )
                        
                        StatCard(
                            title: "Vulnerabilities",
                            value: "\(viewModel.totalVulnerabilities)",
                            icon: "ant.fill",
                            color: .orange
                        )
                        
                        StatCard(
                            title: "Compliance",
                            value: "\(Int(viewModel.complianceScore))%",
                            icon: "doc.badge.gearshape.fill",
                            color: .blue
                        )
                    }
                    .padding(.horizontal)
                    
                    // Threat Trend Chart
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("Threat Activity")
                                .font(.headline)
                            
                            Spacer()
                            
                            Picker("Time Range", selection: $selectedTimeRange) {
                                ForEach(TimeRange.allCases, id: \.self) { range in
                                    Text(range.rawValue).tag(range)
                                }
                            }
                            .pickerStyle(SegmentedPickerStyle())
                            .frame(width: 200)
                        }
                        
                        ThreatTrendChart(data: viewModel.threatTrendData)
                            .frame(height: 200)
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    .padding(.horizontal)
                    
                    // Recent Alerts
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("Recent Alerts")
                                .font(.headline)
                            
                            Spacer()
                            
                            NavigationLink(destination: AlertsView(viewModel: viewModel)) {
                                Text("View All")
                                    .font(.caption)
                                    .foregroundColor(.blue)
                            }
                        }
                        
                        if viewModel.activeAlerts.isEmpty {
                            Text("No active alerts")
                                .foregroundColor(.secondary)
                                .frame(maxWidth: .infinity)
                                .padding()
                        } else {
                            ForEach(viewModel.activeAlerts.prefix(3)) { alert in
                                AlertRow(alert: alert)
                            }
                        }
                    }
                    .padding()
                    .background(Color(.systemGray6))
                    .cornerRadius(12)
                    .padding(.horizontal)
                }
                .padding(.vertical)
            }
            .navigationTitle("Security Dashboard")
            .navigationBarItems(
                trailing: Button(action: viewModel.refreshData) {
                    Image(systemName: "arrow.clockwise")
                }
            )
        }
        .onAppear {
            viewModel.startMonitoring()
        }
    }
}

// MARK: - Security Score Card
struct SecurityScoreCard: View {
    let score: Double
    
    var scoreColor: Color {
        if score >= 90 { return .green }
        else if score >= 70 { return .orange }
        else { return .red }
    }
    
    var body: some View {
        VStack(spacing: 15) {
            HStack {
                VStack(alignment: .leading, spacing: 5) {
                    Text("Security Score")
                        .font(.headline)
                        .foregroundColor(.secondary)
                    
                    Text("\(Int(score))")
                        .font(.system(size: 48, weight: .bold))
                        .foregroundColor(scoreColor)
                }
                
                Spacer()
                
                CircularProgressView(progress: score / 100, color: scoreColor)
                    .frame(width: 80, height: 80)
            }
            
            HStack(spacing: 20) {
                ScoreBadge(label: "Critical", value: 0, color: .red)
                ScoreBadge(label: "High", value: 3, color: .orange)
                ScoreBadge(label: "Medium", value: 12, color: .yellow)
                ScoreBadge(label: "Low", value: 27, color: .green)
            }
        }
        .padding()
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(scoreColor.opacity(0.1))
                .overlay(
                    RoundedRectangle(cornerRadius: 16)
                        .stroke(scoreColor, lineWidth: 2)
                )
        )
    }
}

// MARK: - Stat Card
struct StatCard: View {
    let title: String
    let value: String
    let icon: String
    let color: Color
    
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Image(systemName: icon)
                    .font(.title2)
                    .foregroundColor(color)
                
                Spacer()
            }
            
            Text(value)
                .font(.title2)
                .fontWeight(.bold)
            
            Text(title)
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding()
        .background(Color(.systemGray6))
        .cornerRadius(12)
    }
}

// MARK: - Alerts View
struct AlertsView: View {
    @ObservedObject var viewModel: SecurityViewModel
    @State private var selectedSeverity: AlertSeverity? = nil
    
    var filteredAlerts: [SecurityAlert] {
        if let severity = selectedSeverity {
            return viewModel.activeAlerts.filter { $0.severity == severity }
        }
        return viewModel.activeAlerts
    }
    
    var body: some View {
        NavigationView {
            VStack {
                // Severity Filter
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 10) {
                        FilterChip(
                            title: "All",
                            isSelected: selectedSeverity == nil,
                            action: { selectedSeverity = nil }
                        )
                        
                        ForEach(AlertSeverity.allCases, id: \.self) { severity in
                            FilterChip(
                                title: severity.rawValue.capitalized,
                                isSelected: selectedSeverity == severity,
                                color: severity.color,
                                action: { selectedSeverity = severity }
                            )
                        }
                    }
                    .padding(.horizontal)
                }
                .padding(.vertical, 10)
                
                if filteredAlerts.isEmpty {
                    Spacer()
                    
                    VStack(spacing: 20) {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 60))
                            .foregroundColor(.green)
                        
                        Text("No Active Alerts")
                            .font(.title2)
                            .fontWeight(.semibold)
                        
                        Text("Your systems are secure")
                            .foregroundColor(.secondary)
                    }
                    
                    Spacer()
                } else {
                    List(filteredAlerts) { alert in
                        NavigationLink(destination: AlertDetailView(alert: alert)) {
                            AlertRow(alert: alert)
                        }
                    }
                    .listStyle(PlainListStyle())
                }
            }
            .navigationTitle("Security Alerts")
            .navigationBarItems(
                trailing: Menu {
                    Button(action: { viewModel.markAllAlertsAsRead() }) {
                        Label("Mark All as Read", systemImage: "checkmark.circle")
                    }
                    
                    Button(action: { viewModel.exportAlerts() }) {
                        Label("Export Alerts", systemImage: "square.and.arrow.up")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            )
        }
    }
}

// MARK: - View Model
class SecurityViewModel: ObservableObject {
    @Published var securityScore: Double = 87.5
    @Published var activeThreats = 4
    @Published var protectedAssets = 1198
    @Published var totalAssets = 1247
    @Published var totalVulnerabilities = 42
    @Published var complianceScore: Double = 88.7
    @Published var activeAlerts: [SecurityAlert] = []
    @Published var threatTrendData: [ThreatDataPoint] = []
    
    private var cancellables = Set<AnyCancellable>()
    private let apiService = APIService()
    private var webSocketTask: URLSessionWebSocketTask?
    
    init() {
        loadMockData()
        setupWebSocket()
    }
    
    func startMonitoring() {
        refreshData()
        
        // Refresh data every 30 seconds
        Timer.publish(every: 30, on: .main, in: .common)
            .autoconnect()
            .sink { _ in
                self.refreshData()
            }
            .store(in: &cancellables)
    }
    
    func refreshData() {
        apiService.fetchSecurityPosture()
            .receive(on: DispatchQueue.main)
            .sink(
                receiveCompletion: { _ in },
                receiveValue: { [weak self] posture in
                    self?.updateFromPosture(posture)
                }
            )
            .store(in: &cancellables)
    }
    
    func requestNotificationPermission() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { granted, _ in
            if granted {
                print("Notification permission granted")
            }
        }
    }
    
    private func setupWebSocket() {
        guard let url = URL(string: "ws://localhost:8000/ws/security-feed") else { return }
        
        webSocketTask = URLSession.shared.webSocketTask(with: url)
        webSocketTask?.resume()
        
        receiveWebSocketMessage()
    }
    
    private func receiveWebSocketMessage() {
        webSocketTask?.receive { [weak self] result in
            switch result {
            case .success(let message):
                switch message {
                case .string(let text):
                    if let data = text.data(using: .utf8) {
                        self?.handleWebSocketData(data)
                    }
                case .data(let data):
                    self?.handleWebSocketData(data)
                @unknown default:
                    break
                }
                
                // Continue receiving messages
                self?.receiveWebSocketMessage()
                
            case .failure(let error):
                print("WebSocket error: \(error)")
                // Attempt to reconnect after 5 seconds
                DispatchQueue.main.asyncAfter(deadline: .now() + 5) {
                    self?.setupWebSocket()
                }
            }
        }
    }
    
    private func handleWebSocketData(_ data: Data) {
        // Process real-time security updates
        DispatchQueue.main.async {
            // Update UI with real-time data
            self.processRealtimeUpdate(data)
        }
    }
    
    private func processRealtimeUpdate(_ data: Data) {
        // Parse and update real-time security metrics
        // This would be implemented based on your WebSocket message format
    }
    
    private func updateFromPosture(_ posture: SecurityPosture) {
        securityScore = posture.overallScore
        activeThreats = posture.threatsDetected.investigating
        // Update other properties from API response
    }
    
    func markAllAlertsAsRead() {
        activeAlerts.removeAll()
    }
    
    func exportAlerts() {
        // Export functionality
    }
    
    private func loadMockData() {
        // Load mock data for development
        activeAlerts = [
            SecurityAlert(
                id: "1",
                title: "Suspicious Login Attempt",
                description: "Multiple failed login attempts detected from IP 192.168.1.100",
                severity: .high,
                timestamp: Date(),
                category: "Authentication"
            ),
            SecurityAlert(
                id: "2",
                title: "Outdated SSL Certificate",
                description: "SSL certificate for api.example.com expires in 7 days",
                severity: .medium,
                timestamp: Date().addingTimeInterval(-3600),
                category: "Infrastructure"
            )
        ]
        
        // Generate trend data
        threatTrendData = (0..<24).map { hour in
            ThreatDataPoint(
                timestamp: Date().addingTimeInterval(Double(-hour * 3600)),
                count: Int.random(in: 20...150)
            )
        }
    }
}

// MARK: - Models
struct SecurityAlert: Identifiable {
    let id: String
    let title: String
    let description: String
    let severity: AlertSeverity
    let timestamp: Date
    let category: String
}

enum AlertSeverity: String, CaseIterable {
    case critical, high, medium, low
    
    var color: Color {
        switch self {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .green
        }
    }
}

struct ThreatDataPoint: Identifiable {
    let id = UUID()
    let timestamp: Date
    let count: Int
}

struct SecurityPosture: Codable {
    let overallScore: Double
    let vulnerabilities: VulnerabilityCount
    let compliance: ComplianceScores
    let threatsDetected: ThreatStats
    let assets: AssetStats
    
    struct VulnerabilityCount: Codable {
        let critical: Int
        let high: Int
        let medium: Int
        let low: Int
    }
    
    struct ComplianceScores: Codable {
        let cissBenchmark: Double
        let nistFramework: Double
        let iso27001: Double
    }
    
    struct ThreatStats: Codable {
        let last24h: Int
        let blocked: Int
        let investigating: Int
    }
    
    struct AssetStats: Codable {
        let total: Int
        let monitored: Int
        let atRisk: Int
    }
}

// MARK: - Supporting Views
struct CircularProgressView: View {
    let progress: Double
    let color: Color
    
    var body: some View {
        ZStack {
            Circle()
                .stroke(color.opacity(0.3), lineWidth: 8)
            
            Circle()
                .trim(from: 0, to: progress)
                .stroke(color, style: StrokeStyle(lineWidth: 8, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .animation(.easeOut(duration: 0.5), value: progress)
        }
    }
}

struct ScoreBadge: View {
    let label: String
    let value: Int
    let color: Color
    
    var body: some View {
        VStack(spacing: 4) {
            Text("\(value)")
                .font(.headline)
                .foregroundColor(color)
            
            Text(label)
                .font(.caption2)
                .foregroundColor(.secondary)
        }
    }
}

struct AlertRow: View {
    let alert: SecurityAlert
    
    var body: some View {
        HStack(spacing: 12) {
            Circle()
                .fill(alert.severity.color)
                .frame(width: 10, height: 10)
            
            VStack(alignment: .leading, spacing: 4) {
                Text(alert.title)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                
                Text(alert.description)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(2)
                
                HStack {
                    Label(alert.category, systemImage: "tag.fill")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                    
                    Spacer()
                    
                    Text(alert.timestamp, style: .relative)
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
            
            Spacer()
            
            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundColor(.secondary)
        }
        .padding(.vertical, 8)
    }
}

struct FilterChip: View {
    let title: String
    let isSelected: Bool
    var color: Color = .blue
    let action: () -> Void
    
    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.caption)
                .fontWeight(isSelected ? .semibold : .regular)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(isSelected ? color : Color(.systemGray5))
                .foregroundColor(isSelected ? .white : .primary)
                .cornerRadius(15)
        }
    }
}

struct ThreatTrendChart: View {
    let data: [ThreatDataPoint]
    
    var body: some View {
        Chart(data) { point in
            LineMark(
                x: .value("Time", point.timestamp),
                y: .value("Threats", point.count)
            )
            .foregroundStyle(Color.blue.gradient)
            
            AreaMark(
                x: .value("Time", point.timestamp),
                y: .value("Threats", point.count)
            )
            .foregroundStyle(Color.blue.opacity(0.1).gradient)
        }
        .chartXAxis {
            AxisMarks(values: .stride(by: .hour, count: 6)) { _ in
                AxisValueLabel(format: .dateTime.hour())
            }
        }
    }
}

struct AlertDetailView: View {
    let alert: SecurityAlert
    
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Alert Header
                VStack(alignment: .leading, spacing: 10) {
                    HStack {
                        Circle()
                            .fill(alert.severity.color)
                            .frame(width: 12, height: 12)
                        
                        Text(alert.severity.rawValue.capitalized)
                            .font(.subheadline)
                            .fontWeight(.semibold)
                            .foregroundColor(alert.severity.color)
                        
                        Spacer()
                        
                        Text(alert.timestamp, style: .relative)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    
                    Text(alert.title)
                        .font(.title2)
                        .fontWeight(.bold)
                    
                    Label(alert.category, systemImage: "tag.fill")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .padding()
                .background(Color(.systemGray6))
                .cornerRadius(12)
                
                // Description
                VStack(alignment: .leading, spacing: 10) {
                    Text("Description")
                        .font(.headline)
                    
                    Text(alert.description)
                        .font(.body)
                        .foregroundColor(.secondary)
                }
                .padding()
                
                // Actions
                VStack(spacing: 12) {
                    Button(action: {}) {
                        Label("Investigate", systemImage: "magnifyingglass")
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.blue)
                            .foregroundColor(.white)
                            .cornerRadius(10)
                    }
                    
                    Button(action: {}) {
                        Label("Mark as Resolved", systemImage: "checkmark.circle")
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color.green)
                            .foregroundColor(.white)
                            .cornerRadius(10)
                    }
                    
                    Button(action: {}) {
                        Label("Create Ticket", systemImage: "ticket")
                            .frame(maxWidth: .infinity)
                            .padding()
                            .background(Color(.systemGray5))
                            .foregroundColor(.primary)
                            .cornerRadius(10)
                    }
                }
                .padding()
            }
        }
        .navigationTitle("Alert Details")
        .navigationBarTitleDisplayMode(.inline)
    }
}

// Placeholder views for other tabs
struct VulnerabilitiesView: View {
    @ObservedObject var viewModel: SecurityViewModel
    
    var body: some View {
        NavigationView {
            Text("Vulnerabilities Management")
                .navigationTitle("Vulnerabilities")
        }
    }
}

struct ComplianceView: View {
    @ObservedObject var viewModel: SecurityViewModel
    
    var body: some View {
        NavigationView {
            Text("Compliance Dashboard")
                .navigationTitle("Compliance")
        }
    }
}

struct ActionsView: View {
    @ObservedObject var viewModel: SecurityViewModel
    
    var body: some View {
        NavigationView {
            VStack(spacing: 20) {
                Button(action: {}) {
                    Label("Run Security Scan", systemImage: "magnifyingglass.circle.fill")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.blue)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
                
                Button(action: {}) {
                    Label("Generate Report", systemImage: "doc.text.fill")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.green)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
                
                Button(action: {}) {
                    Label("Update Policies", systemImage: "shield.checkered")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(Color.orange)
                        .foregroundColor(.white)
                        .cornerRadius(12)
                }
                
                Spacer()
            }
            .padding()
            .navigationTitle("Quick Actions")
        }
    }
}

struct SettingsView: View {
    var body: some View {
        NavigationView {
            Form {
                Section("Notifications") {
                    Toggle("Push Notifications", isOn: .constant(true))
                    Toggle("Email Alerts", isOn: .constant(true))
                    Toggle("SMS Alerts", isOn: .constant(false))
                }
                
                Section("Security") {
                    Toggle("Biometric Authentication", isOn: .constant(true))
                    Toggle("Auto-lock", isOn: .constant(true))
                }
            }
            .navigationTitle("Settings")
        }
    }
}

// MARK: - API Service
class APIService {
    private let baseURL = "http://localhost:8000/api/v1"
    
    func fetchSecurityPosture() -> AnyPublisher<SecurityPosture, Error> {
        guard let url = URL(string: "\(baseURL)/security-posture") else {
            return Fail(error: URLError(.badURL))
                .eraseToAnyPublisher()
        }
        
        var request = URLRequest(url: url)
        request.setValue("Bearer \(getAuthToken())", forHTTPHeaderField: "Authorization")
        
        return URLSession.shared.dataTaskPublisher(for: request)
            .map(\.data)
            .decode(type: SecurityPosture.self, decoder: JSONDecoder())
            .eraseToAnyPublisher()
    }
    
    private func getAuthToken() -> String {
        // Get stored auth token
        return UserDefaults.standard.string(forKey: "authToken") ?? ""
    }
}