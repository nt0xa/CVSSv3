//
//  SecondViewController.swift
//  CVSS
//
//  Created by Anton Prokhorov on 28/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import UIKit

class TemporalViewController: UIViewController, FormDelegate {
    
    @IBOutlet weak var exploitCodeMaturity: UISegmentedControl!
    @IBOutlet weak var remediationLevel: UISegmentedControl!
    @IBOutlet weak var reportConfidence: UISegmentedControl!
    
    var cvss: CVSS {
        get {
            return (self.tabBarController as! TabBarViewController).cvss
        }
    }
    
    var previousScore: Float {
        get {
            switch (self.tabBarController as! TabBarViewController).previousSelectedItemIndex {
            case 0:
                return cvss.baseScore()
            case 1:
                return cvss.temporalScore()
            case 2:
                return cvss.enviromentalScore()
            default:
                return 0
            }
        }
    }
    
    var result: ResultDelegate?
    
    override func viewWillAppear(_ animated: Bool) {
        let score = previousScore
        result?.update(
            score: score,
            severity: CVSS.Severity.fromScore(score).description,
            vector: cvss.description,
            animated: false
        )
        syncForm()
    }
    
    override func viewDidAppear(_ animated: Bool) {
        updateResult()
    }
    
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let vc = segue.destination as? ResultViewController {
            result = vc
        }
    }
    
    func syncForm() {
        exploitCodeMaturity.selectedSegmentIndex = (cvss.exploitCodeMaturity?.rawValue ?? -1) + 1
        remediationLevel.selectedSegmentIndex = (cvss.remediationLevel?.rawValue ?? -1) + 1
        reportConfidence.selectedSegmentIndex = (cvss.reportConfidence?.rawValue ?? -1) + 1
    }
    
    func updateResult() {
        let score = cvss.temporalScore()
        result?.update(
            score: score,
            severity: CVSS.Severity.fromScore(score).description,
            vector: cvss.description,
            animated: true
        )
    }
    
    @IBAction func exploitCodeMaturityValueChanged(_ sender: UISegmentedControl) {
        cvss.exploitCodeMaturity = CVSS.ExploitCodeMaturity(
            rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func remediationLevelValueChanged(_ sender: UISegmentedControl) {
        cvss.remediationLevel = CVSS.RemediationLevel(
            rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func reportConfidenceValueChanged(_ sender: UISegmentedControl) {
        cvss.reportConfidence = CVSS.ReportConfidence(
            rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
}

