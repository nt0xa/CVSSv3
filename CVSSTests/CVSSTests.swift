//
//  CVSSTests.swift
//  CVSSTests
//
//  Created by Anton Prokhorov on 28/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import XCTest
@testable import CVSS

class CVSSTests: XCTestCase {
    
    func testToVectorConversion() {
        let tests: [(cvss: CVSS, expected: String)] = [
            (
                CVSS(av: .network, ac: .high, pr: .low, ui: .none, s: .changed, c: .low, i: .high, a: .none),
                "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:N"
            ),
            (
                CVSS(av: .adjacent, ac: .low, pr: .none, ui: .required, s: .unchanged, c: .none, i: .none, a: .high),
                "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"
            ),
            (
                CVSS(av: .phisical, ac: .low, pr: .none, ui: .required, s: .unchanged, c: .low, i: .low, a: .high,
                     e: .poc, rl: .officialFix),
                "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H/E:P/RL:O"
            ),
            (
                CVSS(av: .phisical, ac: .low, pr: .none, ui: .required, s: .unchanged, c: .low, i: .low, a: .high,
                     e: .high, rc: .unknown),
                "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H/E:H/RC:U"
            ),
            (
                CVSS(av: .phisical, ac: .low, pr: .none, ui: .required, s: .unchanged, c: .low, i: .low, a: .high,
                     e: .high, rc: .unknown,
                     cr: .high,
                     mac: .high),
                "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H/E:H/RC:U/CR:H/MAC:H"
            ),
            (
                CVSS(av: .network, ac: .high, pr: .low, ui: .none, s: .changed, c: .low, i: .high, a: .none,
                     e: .functional, rl: .workaround, rc: .confirmed,
                     cr: .low, ir: .high, ar: .low,
                     mav: .adjacent, mac: .low, mpr: .high, mui: .required,
                     ms: .unchanged, mc: .high, mi: .low, ma: .high),
                "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:N/E:F/RL:W/RC:C/CR:L/IR:H/AR:L/MAV:A/MAC:L/MPR:H/MUI:R/MS:U/MC:H/MI:L/MA:H"
            ),
        ]
        
        for test in tests {
            let actual = test.cvss.description
            XCTAssertEqual(actual, test.expected)
        }
    }
    
    func testFromVectorConversion() {
        let tests: [(vector: String, expected: CVSS)] = [
            (
                "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:N",
                CVSS(av: .network, ac: .high, pr: .low, ui: .none, s: .changed, c: .low, i: .high, a: .none)
            ),
            (
                "CVSS:3.0/AV:A/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
                CVSS(av: .adjacent, ac: .low, pr: .none, ui: .required, s: .unchanged, c: .none, i: .none, a: .high)
            ),
            (
                "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H/E:P/RL:O",
                CVSS(av: .phisical, ac: .low, pr: .none, ui: .required, s: .unchanged, c: .low, i: .low, a: .high,
                     e: .poc, rl: .officialFix)
            ),
            (
                "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H/E:H/RC:U",
                CVSS(av: .phisical, ac: .low, pr: .none, ui: .required, s: .unchanged, c: .low, i: .low, a: .high,
                     e: .high, rc: .unknown)
            ),
            (
                "CVSS:3.0/AV:P/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:H/E:H/RC:U/CR:H/MAC:H",
                CVSS(av: .phisical, ac: .low, pr: .none, ui: .required, s: .unchanged, c: .low, i: .low, a: .high,
                     e: .high, rc: .unknown,
                     cr: .high,
                     mac: .high)
            ),
            (
                "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:H/A:N/E:F/RL:W/RC:C/CR:L/IR:H/AR:L/MAV:A/MAC:L/MPR:H/MUI:R/MS:U/MC:H/MI:L/MA:H",
                CVSS(av: .network, ac: .high, pr: .low, ui: .none, s: .changed, c: .low, i: .high, a: .none,
                     e: .functional, rl: .workaround, rc: .confirmed,
                     cr: .low, ir: .high, ar: .low,
                     mav: .adjacent, mac: .low, mpr: .high, mui: .required,
                     ms: .unchanged, mc: .high, mi: .low, ma: .high)
            ),
        ]
        
        for test in tests {
            let actual = CVSS.fromVector(test.vector)!
            XCTAssertEqual(actual, test.expected)
        }
    }
    
    func testScoresSimple() {
        let bundle = Bundle(for: type(of: self))
        let path = bundle.path(forResource: "vectors-simple", ofType: "json")!
        let data = NSData(contentsOfFile: path)!
        
        struct Scores: Codable {
            let base: Float
            let temporal: Float
            let environmental: Float
        }
        
        struct Test: Codable {
            let vector: String
            let scores: Scores
        }

        let tests = try! JSONDecoder().decode([Test].self, from: data as Data)
        
        for test in tests {
            let actual = CVSS.fromVector(test.vector)!
            XCTAssertEqual(actual.baseScore(), test.scores.base)
            XCTAssertEqual(actual.temporalScore(), test.scores.temporal)
            XCTAssertEqual(actual.enviromentalScore(), test.scores.environmental)
        }
    }
    
    func testScoresRandom() {
        let bundle = Bundle(for: type(of: self))
        let path = bundle.path(forResource: "vectors-random", ofType: "json")!
        let data = NSData(contentsOfFile: path)!
        
        struct Scores: Codable {
            let base: Float
            let temporal: Float
            let environmental: Float
        }
        
        struct Test: Codable {
            let vector: String
            let scores: Scores
        }
        
        let tests = try! JSONDecoder().decode([Test].self, from: data as Data)
        
        for test in tests {
            let actual = CVSS.fromVector(test.vector)!
            XCTAssertEqual(actual.baseScore(), test.scores.base)
            XCTAssertEqual(actual.temporalScore(), test.scores.temporal)
            XCTAssertEqual(actual.enviromentalScore(), test.scores.environmental)
        }
    }
    
}
