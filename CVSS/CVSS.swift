//
//  CVSS.swift
//  CVSS
//
//  Created by Anton Prokhorov on 29/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import Foundation

class CVSS: CustomStringConvertible, Equatable {
    
    //
    //  Base
    //
    
    enum AttackVector: Int, CustomStringConvertible {
        case network
        case adjacent
        case local
        case phisical
        
        func value() -> Float {
            switch self {
            case .network:
                return 0.85
            case .adjacent:
                return 0.62
            case .local:
                return 0.55
            case .phisical:
                return 0.2
            }
        }
        
        static func fromString(_ description: String) -> AttackVector? {
            switch description {
            case "N":
                return .network
            case "A":
                return .adjacent
            case "L":
                return .local
            case "P":
                return .phisical
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .network:
                return "N"
            case .adjacent:
                return "A"
            case .local:
                return "L"
            case .phisical:
                return "P"
            }
        }
    }
    
    enum AttackComplexity: Int, CustomStringConvertible {
        case low
        case high
        
        func value() -> Float {
            switch self {
            case .low:
                return 0.77
            case .high:
                return 0.44
            }
        }
        
        static func fromString(_ description: String) -> AttackComplexity? {
            switch description {
            case "L":
                return .low
            case "H":
                return .high
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .low:
                return "L"
            case .high:
                return "H"
            }
        }
    }
    
    enum PrivilegeRequired: Int, CustomStringConvertible {
        case none
        case low
        case high
        
        func value(_ scope: Scope) -> Float {
            switch self {
            case .none:
                return 0.85
            case .low:
                return scope == .unchanged ? 0.62 : 0.68
            case .high:
                return scope == .unchanged ? 0.27 : 0.5
            }
        }
        
        static func fromString(_ description: String) -> PrivilegeRequired? {
            switch description {
            case "N":
                return PrivilegeRequired.none
            case "L":
                return .low
            case "H":
                return .high
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .none:
                return "N"
            case .low:
                return "L"
            case .high:
                return "H"
            }
        }
    }
    
    enum UserInteraction: Int, CustomStringConvertible {
        case none
        case required
        
        func value() -> Float {
            switch self {
            case .none:
                return 0.85
            case .required:
                return 0.62
            }
        }
        
        static func fromString(_ description: String) -> UserInteraction? {
            switch description {
            case "N":
                return UserInteraction.none
            case "R":
                return .required
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .none:
                return "N"
            case .required:
                return "R"
            }
        }
    }
    
    enum Scope: Int, CustomStringConvertible {
        case unchanged
        case changed
        
        static func fromString(_ description: String) -> Scope? {
            switch description {
            case "U":
                return .unchanged
            case "C":
                return .changed
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .unchanged:
                return "U"
            case .changed:
                return "C"
            }
        }
    }
    
    enum Confidentiality: Int, CustomStringConvertible {
        case none
        case low
        case high
        
        func value() -> Float {
            switch self {
            case .none:
                return 0
            case .low:
                return 0.22
            case .high:
                return 0.56
            }
        }
        
        static func fromString(_ description: String) -> Confidentiality? {
            switch description {
            case "N":
                return Confidentiality.none
            case "L":
                return .low
            case "H":
                return .high
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .none:
                return "N"
            case .low:
                return "L"
            case .high:
                return "H"
            }
        }
    }
    
    enum Integrity: Int, CustomStringConvertible {
        case none
        case low
        case high
        
        func value() -> Float {
            switch self {
            case .none:
                return 0
            case .low:
                return 0.22
            case .high:
                return 0.56
            }
        }
        
        static func fromString(_ description: String) -> Integrity? {
            switch description {
            case "N":
                return Integrity.none
            case "L":
                return .low
            case "H":
                return .high
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .none:
                return "N"
            case .low:
                return "L"
            case .high:
                return "H"
            }
        }
    }
    
    enum Availability: Int, CustomStringConvertible {
        case none
        case low
        case high
        
        func value() -> Float {
            switch self {
            case .none:
                return 0
            case .low:
                return 0.22
            case .high:
                return 0.56
            }
        }
        
        static func fromString(_ description: String) -> Availability? {
            switch description {
            case "N":
                return Availability.none
            case "L":
                return .low
            case "H":
                return .high
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .none:
                return "N"
            case .low:
                return "L"
            case .high:
                return "H"
            }
        }
    }
    
    //
    //  Temporary
    //
    
    enum ExploitCodeMaturity: Int, CustomStringConvertible {
        case unproven
        case poc
        case functional
        case high
        
        func value() -> Float {
            switch self {
            case .unproven:
                return 0.91
            case .poc:
                return 0.94
            case .functional:
                return 0.97
            case .high:
                return 1
            }
        }
        
        static func fromString(_ description: String) -> ExploitCodeMaturity? {
            switch description {
            case "U":
                return .unproven
            case "P":
                return .poc
            case "F":
                return .functional
            case "H":
                return .high
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .unproven:
                return "U"
            case .poc:
                return "P"
            case .functional:
                return "F"
            case .high:
                return "H"
            }
        }
    }
    
    enum RemediationLevel: Int, CustomStringConvertible {
        case officialFix
        case temporaryFix
        case workaround
        case unavailable
        
        func value() -> Float {
            switch self {
            case .officialFix:
                return 0.95
            case .temporaryFix:
                return 0.96
            case .workaround:
                return 0.97
            case .unavailable:
                return 1
            }
        }
        
        static func fromString(_ description: String) -> RemediationLevel? {
            switch description {
            case "O":
                return .officialFix
            case "T":
                return .temporaryFix
            case "W":
                return .workaround
            case "U":
                return .unavailable
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .officialFix:
                return "O"
            case .temporaryFix:
                return "T"
            case .workaround:
                return "W"
            case .unavailable:
                return "U"
            }
        }
    }
    
    enum ReportConfidence: Int, CustomStringConvertible {
        case unknown
        case resonable
        case confirmed

        func value() -> Float {
            switch self {
            case .unknown:
                return 0.92
            case .resonable:
                return 0.96
            case .confirmed:
                return 1
            }
        }
        
        static func fromString(_ description: String) -> ReportConfidence? {
            switch description {
            case "U":
                return .unknown
            case "R":
                return .resonable
            case "C":
                return .confirmed
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .unknown:
                return "U"
            case .resonable:
                return "R"
            case .confirmed:
                return "C"
            }
        }
    }
    
    //
    //  Environmental
    //
    
    enum ConfidentialityRequirement: Int, CustomStringConvertible {
        case low
        case medium
        case high
        
        func value() -> Float {
            switch self {
            case .low:
                return 0.5
            case .medium:
                return 1
            case .high:
                return 1.5
            }
        }
        
        static func fromString(_ description: String) -> ConfidentialityRequirement? {
            switch description {
            case "L":
                return .low
            case "M":
                return .medium
            case "H":
                return .high
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .low:
                return "L"
            case .medium:
                return "M"
            case .high:
                return "H"
            }
        }
    }
    
    enum IntegrityRequirement: Int, CustomStringConvertible {
        case low
        case medium
        case high
        
        func value() -> Float {
            switch self {
            case .low:
                return 0.5
            case .medium:
                return 1
            case .high:
                return 1.5
            }
        }
        
        static func fromString(_ description: String) -> IntegrityRequirement? {
            switch description {
            case "L":
                return .low
            case "M":
                return .medium
            case "H":
                return .high
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .low:
                return "L"
            case .medium:
                return "M"
            case .high:
                return "H"
            }
        }
    }
    
    enum AvailabilityRequirement: Int, CustomStringConvertible {
        case low
        case medium
        case high
        
        func value() -> Float {
            switch self {
            case .low:
                return 0.5
            case .medium:
                return 1
            case .high:
                return 1.5
            }
        }
        
        static func fromString(_ description: String) -> AvailabilityRequirement? {
            switch description {
            case "L":
                return .low
            case "M":
                return .medium
            case "H":
                return .high
            default:
                return nil
            }
        }
        
        var description: String {
            switch self {
            case .low:
                return "L"
            case .medium:
                return "M"
            case .high:
                return "H"
            }
        }
    }
        
    //
    //  Common
    //
    
    enum Severity: CustomStringConvertible {
        case none
        case low
        case medium
        case high
        case critical
        
        static func fromScore(_ score: Float) -> Severity {
            if score >= 0.1 && score <= 3.9 {
                return .low
            } else if score >= 4.0 && score <= 6.9 {
                return .medium
            } else if score >= 7.0 && score <= 8.9 {
                return .high
            } else if score >= 9.0 && score <= 10.0 {
                return .critical
            } else {
                return .none
            }
        }
        
        var description: String {
            switch self {
            case .none:
                return ""
            case .low:
                return "low"
            case .medium:
                return "medium"
            case .high:
                return "high"
            case .critical:
                return "critical"
            }
        }
    }

    static let vectorSubPattern = """
        AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|\
        E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|\
        [CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH]
        """
    static let vectorPattern = "^CVSS:3\\.0\\/((" + vectorSubPattern + ")\\/)*(" + vectorSubPattern + ")$"
    
    // Base
    var attackVector: AttackVector = .network
    var attackComplexity: AttackComplexity = .low
    var privilegeRequired: PrivilegeRequired = .none
    var userInteraction: UserInteraction = .none
    var scope: Scope = .unchanged
    var confidentiality: Confidentiality = .none
    var integrity: Integrity = .none
    var availability: Availability = .none
    
    // Temporal
    var exploitCodeMaturity: ExploitCodeMaturity? = nil
    var remediationLevel: RemediationLevel? = nil
    var reportConfidence: ReportConfidence? = nil
    
    // Environmental
    var confidentialityRequirement: ConfidentialityRequirement? = nil
    var integrityRequirement: IntegrityRequirement? = nil
    var availabilityRequirement: AvailabilityRequirement? = nil
    var modifiedAttackVector: AttackVector? = nil
    var modifiedAttackComplexity: AttackComplexity? = nil
    var modifiedPrivilegeRequired: PrivilegeRequired? = nil
    var modifiedUserInteraction: UserInteraction? = nil
    var modifiedScope: Scope? = nil
    var modifiedConfidentiality: Confidentiality? = nil
    var modifiedIntegrity: Integrity? = nil
    var modifiedAvailability: Availability? = nil
    
    public static func == (lhs: CVSS, rhs: CVSS) -> Bool {
        let pairs: [(lhs: Int?, rhs: Int?)] = [
            (lhs.attackVector.rawValue,                 rhs.attackVector.rawValue),
            (lhs.attackComplexity.rawValue,             rhs.attackComplexity.rawValue),
            (lhs.privilegeRequired.rawValue,            rhs.privilegeRequired.rawValue),
            (lhs.userInteraction.rawValue,              rhs.userInteraction.rawValue),
            (lhs.scope.rawValue,                        rhs.scope.rawValue),
            (lhs.confidentiality.rawValue,              rhs.confidentiality.rawValue),
            (lhs.integrity.rawValue,                    rhs.integrity.rawValue),
            (lhs.availability.rawValue,                 rhs.availability.rawValue),
            (lhs.exploitCodeMaturity?.rawValue,         rhs.exploitCodeMaturity?.rawValue),
            (lhs.remediationLevel?.rawValue,            rhs.remediationLevel?.rawValue),
            (lhs.reportConfidence?.rawValue,            rhs.reportConfidence?.rawValue),
            (lhs.confidentialityRequirement?.rawValue,  rhs.confidentialityRequirement?.rawValue),
            (lhs.integrityRequirement?.rawValue,        rhs.integrityRequirement?.rawValue),
            (lhs.availabilityRequirement?.rawValue,     rhs.availabilityRequirement?.rawValue),
            (lhs.modifiedAttackVector?.rawValue,        rhs.modifiedAttackVector?.rawValue),
            (lhs.modifiedAttackComplexity?.rawValue,    rhs.modifiedAttackComplexity?.rawValue),
            (lhs.modifiedPrivilegeRequired?.rawValue,   rhs.modifiedPrivilegeRequired?.rawValue),
            (lhs.modifiedUserInteraction?.rawValue,     rhs.modifiedUserInteraction?.rawValue),
            (lhs.modifiedScope?.rawValue,               rhs.modifiedScope?.rawValue),
            (lhs.modifiedConfidentiality?.rawValue,     rhs.modifiedConfidentiality?.rawValue),
            (lhs.modifiedIntegrity?.rawValue,           rhs.modifiedIntegrity?.rawValue),
            (lhs.modifiedAvailability?.rawValue,        rhs.modifiedAvailability?.rawValue),
        ]
        
        for pair in pairs {
            if pair.lhs != pair.rhs {
                return false
            }
        }
        
        return true
    }
    
    class func roundUp(_ value: Float) -> Float {
        let temp = round(value * 100000) / 100000
        return (temp * 10).rounded(.up) / 10
    }
    
    class func fromVector(_ vector: String) -> CVSS? {
        if vector.range(of: vectorPattern, options: .regularExpression, range: nil, locale: nil) == nil {
            return nil
        }
        
        let cvss = CVSS()

        let parts = vector
            .replacingOccurrences(of: "CVSS:3.0/", with: "")
            .components(separatedBy: "/")
        
        for part in parts {
            let arr = part.components(separatedBy: ":")
            let id = arr[0]
            let value = arr[1]
            
            switch id {
            // Base
            case "AV":
                cvss.attackVector = AttackVector.fromString(value)!
            case "AC":
                cvss.attackComplexity = AttackComplexity.fromString(value)!
            case "PR":
                cvss.privilegeRequired = PrivilegeRequired.fromString(value)!
            case "UI":
                cvss.userInteraction = UserInteraction.fromString(value)!
            case "S":
                cvss.scope = Scope.fromString(value)!
            case "C":
                cvss.confidentiality = Confidentiality.fromString(value)!
            case "I":
                cvss.integrity = Integrity.fromString(value)!
            case "A":
                cvss.availability = Availability.fromString(value)!
            
            // Temporal
            case "E":
                cvss.exploitCodeMaturity = ExploitCodeMaturity.fromString(value)
            case "RL":
                cvss.remediationLevel = RemediationLevel.fromString(value)
            case "RC":
                cvss.reportConfidence = ReportConfidence.fromString(value)
                
            // Environmental
            case "CR":
                cvss.confidentialityRequirement = ConfidentialityRequirement.fromString(value)
            case "IR":
                cvss.integrityRequirement = IntegrityRequirement.fromString(value)
            case "AR":
                cvss.availabilityRequirement = AvailabilityRequirement.fromString(value)
                
            case "MAV":
                cvss.modifiedAttackVector = AttackVector.fromString(value)
            case "MAC":
                cvss.modifiedAttackComplexity = AttackComplexity.fromString(value)
            case "MPR":
                cvss.modifiedPrivilegeRequired = PrivilegeRequired.fromString(value)
            case "MUI":
                cvss.modifiedUserInteraction = UserInteraction.fromString(value)
            case "MS":
                cvss.modifiedScope = Scope.fromString(value)
            case "MC":
                cvss.modifiedConfidentiality = Confidentiality.fromString(value)
            case "MI":
                cvss.modifiedIntegrity = Integrity.fromString(value)
            case "MA":
                cvss.modifiedAvailability = Availability.fromString(value)
                
            default:
                break
            }
        }
        
        return cvss
    }
    
    var description: String {
        let fields: [(String, CustomStringConvertible)] = [
            // Base
            ("AV", attackVector),
            ("AC", attackComplexity),
            ("PR", privilegeRequired),
            ("UI", userInteraction),
            ("S", scope),
            ("C", confidentiality),
            ("I", integrity),
            ("A", availability),
            
            // Temporary
            ("E", exploitCodeMaturity ?? ""),
            ("RL", remediationLevel ?? ""),
            ("RC", reportConfidence ?? ""),
            
            // Environmental
            ("CR", confidentialityRequirement ?? ""),
            ("IR", integrityRequirement ?? ""),
            ("AR", availabilityRequirement ?? ""),
            ("MAV", modifiedAttackVector ?? ""),
            ("MAC", modifiedAttackComplexity ?? ""),
            ("MPR", modifiedPrivilegeRequired ?? ""),
            ("MUI", modifiedUserInteraction ?? ""),
            ("MS", modifiedScope ?? ""),
            ("MC", modifiedConfidentiality ?? ""),
            ("MI", modifiedIntegrity ?? ""),
            ("MA", modifiedAvailability ?? ""),
        ]
        
        var vector = "CVSS:3.0"
        
        for (id, value) in fields {
            if value.description.isEmpty {
                continue
            }
            vector += "/\(id):\(value)"
        }

        return vector
    }
    
    init() {}
    
    init(
        // Base
        av: AttackVector,
        ac: AttackComplexity,
        pr: PrivilegeRequired,
        ui: UserInteraction,
        s: Scope,
        c: Confidentiality,
        i: Integrity,
        a: Availability,
        
        // Temporal
        e: ExploitCodeMaturity? = nil,
        rl: RemediationLevel? = nil,
        rc: ReportConfidence? = nil,
        
        // Environmental
        cr: ConfidentialityRequirement? = nil,
        ir: IntegrityRequirement? = nil,
        ar: AvailabilityRequirement? = nil,
        
        mav: AttackVector? = nil,
        mac: AttackComplexity? = nil,
        mpr: PrivilegeRequired? = nil,
        mui: UserInteraction? = nil,
        ms: Scope? = nil,
        mc: Confidentiality? = nil,
        mi: Integrity? = nil,
        ma: Availability? = nil
    ) {
        // Base
        attackVector = av
        attackComplexity = ac
        privilegeRequired = pr
        userInteraction = ui
        scope = s
        confidentiality = c
        integrity = i
        availability = a
        
        // Temporal
        exploitCodeMaturity = e
        remediationLevel = rl
        reportConfidence = rc
        
        // Environmental
        confidentialityRequirement = cr
        integrityRequirement = ir
        availabilityRequirement = ar
        
        modifiedAttackVector = mav
        modifiedAttackComplexity = mac
        modifiedPrivilegeRequired = mpr
        modifiedUserInteraction = mui
        modifiedScope = ms
        modifiedConfidentiality = mc
        modifiedIntegrity = mi
        modifiedAvailability = ma
    }
    
    private func iscBase(c: Float, i: Float, a: Float) -> Float {
        return 1 - (1 - c) * (1 - i) * (1 - a)
    }
    
    private func iscModified(c: Float, cr: Float,
                             i: Float, ir: Float,
                             a: Float, ar: Float) -> Float {
        return min(iscBase(c: c * cr, i: i * ir, a: a * ar), 0.915)
    }
    
    private func isc(iscAny: Float, scope: Scope) -> Float {
        switch scope {
        case .unchanged:
            return 6.42 * iscAny
        case .changed:
            return 7.52 * (iscAny - 0.029) - 3.25 * pow(iscAny - 0.02, 15)
        }
    }
    
    private func esc(av: Float, ac: Float, pr: Float, ui: Float) -> Float {
        return 8.22 * av * ac * pr * ui
    }
    
    private func score(iscAny: Float, esc: Float, scope: Scope) -> Float {
        let isc = self.isc(iscAny: iscAny, scope: scope)
        
        if isc <= 0 {
            return 0
        }
        
        switch scope {
        case .unchanged:
            return CVSS.roundUp(min(isc + esc, 10))
        case .changed:
            return CVSS.roundUp(min(1.08 * (isc + esc), 10))
        }
    }
    
    func baseScore() -> Float {
        return score(
            iscAny: iscBase(
                c: confidentiality.value(),
                i: integrity.value(),
                a: availability.value()
            ),
            esc: esc(
                av: attackVector.value(),
                ac: attackComplexity.value(),
                pr: privilegeRequired.value(scope),
                ui: userInteraction.value()
            ),
            scope: scope
        )
    }
    
    private func temporal(score: Float, e: Float, rl: Float, rc: Float) -> Float {
        return CVSS.roundUp(score * e * rl * rc)
    }
    
    func temporalScore() -> Float {
        return temporal(
            score: baseScore(),
            e: exploitCodeMaturity?.value() ?? 1,
            rl: remediationLevel?.value() ?? 1,
            rc: reportConfidence?.value() ?? 1
        )
    }
    
    func enviromentalScore() -> Float {
        let scope = modifiedScope ?? self.scope
        
        let score = self.score(
            iscAny: iscModified(
                c:  (modifiedConfidentiality ?? confidentiality).value(),
                cr: confidentialityRequirement?.value() ?? 1,
                i:  (modifiedIntegrity ?? integrity).value(),
                ir: integrityRequirement?.value() ?? 1,
                a:  (modifiedAvailability ?? availability).value(),
                ar: availabilityRequirement?.value() ?? 1
            ),
            esc: esc(
                av: (modifiedAttackVector ?? attackVector).value(),
                ac: (modifiedAttackComplexity ?? attackComplexity).value(),
                pr: (modifiedPrivilegeRequired ?? privilegeRequired).value(scope),
                ui: (modifiedUserInteraction ?? userInteraction).value()
            ),
            scope: scope
        )
        
        return temporal(
            score: score,
            e: exploitCodeMaturity?.value() ?? 1,
            rl: remediationLevel?.value() ?? 1,
            rc: reportConfidence?.value() ?? 1
        )
    }
}

