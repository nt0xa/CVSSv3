//
//  CVSS.swift
//  CVSS
//
//  Created by Anton Prokhorov on 29/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import Foundation

class CVSS {
    
    //
    // Base score
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
        
        var description: String {
            switch self {
            case .network:
                return "AV:N"
            case .adjacent:
                return "AV:A"
            case .local:
                return "AV:L"
            case .phisical:
                return "AV:P"
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
        
        var description: String {
            switch self {
            case .low:
                return "AC:L"
            case .high:
                return "AC:H"
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
        
        var description: String {
            switch self {
            case .none:
                return "PR:N"
            case .low:
                return "PR:L"
            case .high:
                return "PR:H"
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
        
        var description: String {
            switch self {
            case .none:
                return "UI:N"
            case .required:
                return "UI:R"
            }
        }
    }
    
    enum Scope: Int, CustomStringConvertible {
        case unchanged
        case changed
        
        var description: String {
            switch self {
            case .unchanged:
                return "S:U"
            case .changed:
                return "S:C"
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
        
        var description: String {
            switch self {
            case .none:
                return "C:N"
            case .low:
                return "C:L"
            case .high:
                return "C:H"
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
        
        var description: String {
            switch self {
            case .none:
                return "I:N"
            case .low:
                return "I:L"
            case .high:
                return "I:H"
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
        
        var description: String {
            switch self {
            case .none:
                return "A:N"
            case .low:
                return "A:L"
            case .high:
                return "A:H"
            }
        }
    }
    
    //
    // Temporary score
    //
    
    enum ExploitCodeMaturity: Int, CustomStringConvertible {
        case notDefined
        case unproven
        case poc
        case functional
        case high
        
        func value() -> Float {
            switch self {
            case .notDefined:
                return 1
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
        
        var description: String {
            switch self {
            case .notDefined:
                return ""
            case .unproven:
                return "E:U"
            case .poc:
                return "E:P"
            case .functional:
                return "E:F"
            case .high:
                return "E:H"
            }
        }
    }
    
    enum RemediationLevel: Int, CustomStringConvertible {
        case notDefined
        case officalFix
        case temporaryFix
        case workaround
        case unavailable
        
        func value() -> Float {
            switch self {
            case .notDefined:
                return 1
            case .officalFix:
                return 0.95
            case .temporaryFix:
                return 0.96
            case .workaround:
                return 0.97
            case .unavailable:
                return 1
            }
        }
        
        var description: String {
            switch self {
            case .notDefined:
                return ""
            case .unavailable:
                return "RL:U"
            case .workaround:
                return "RL:W"
            case .temporaryFix:
                return "RL:T"
            case .officalFix:
                return "RL:O"
            }
        }
    }
    
    enum ReportConfidence: Int, CustomStringConvertible {
        case notDefined
        case unknown
        case resonable
        case confirmed

        func value() -> Float {
            switch self {
            case .notDefined:
                return 1
            case .unknown:
                return 0.92
            case .resonable:
                return 0.96
            case .confirmed:
                return 1
            }
        }
        
        var description: String {
            switch self {
            case .notDefined:
                return ""
            case .confirmed:
                return "RC:C"
            case .resonable:
                return "RC:R"
            case .unknown:
                return "RC:U"
            }
        }
    }
    
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
    var exploitCodeMaturity: ExploitCodeMaturity = .notDefined
    var remediationLevel: RemediationLevel = .notDefined
    var reportConfidence: ReportConfidence = .notDefined
    
    class func roundUp(_ value: Float) -> Float {
        return (value * 10).rounded(.up) / 10
    }
    
    func severity() -> Severity {
        return Severity.fromScore(baseScore())
    }
    
    func toVector() -> String {
        let mirror = Mirror(reflecting: self)
        var vector = ""
        for attr in mirror.children {
            let value = "/\(attr.value)"
            if !value.isEmpty {
                vector += value
            }
        }
        return vector
    }
    
    func baseScore() -> Float {
        let iscBase = 1 - ((1 - confidentiality.value()) * (1 - integrity.value()) * (1 - availability.value()))
        
        var isc: Float
        switch scope {
        case .unchanged:
            isc = 6.42 * iscBase
        case .changed:
            isc = 7.52 * (iscBase - 0.029) - 3.25 * pow(iscBase - 0.02, 15)
        }
        
        if isc <= 0 {
            return 0
        }
        
        let esc = 8.22 * attackVector.value() * attackComplexity.value() *
            privilegeRequired.value(scope) * userInteraction.value()
        
        switch scope {
        case .unchanged:
            return CVSS.roundUp(min(isc + esc, 10))
        case .changed:
            return CVSS.roundUp(min(1.08 * (isc + esc), 10))
        }
    }
    
    func temporalScore() -> Float {
        return CVSS.roundUp(baseScore() * exploitCodeMaturity.value() * remediationLevel.value() * reportConfidence.value())
    }
}

