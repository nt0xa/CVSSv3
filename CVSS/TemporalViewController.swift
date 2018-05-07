//
//  SecondViewController.swift
//  CVSS
//
//  Created by Anton Prokhorov on 28/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import UIKit

class TemporalViewController: UIViewController {
    
    @IBOutlet weak var exploitCodeMaturity: UISegmentedControl!
    @IBOutlet weak var remediationLevel: UISegmentedControl!
    @IBOutlet weak var reportConfidence: UISegmentedControl!
    
    var cvss: CVSS {
        get {
            return (self.tabBarController as! TabBarViewController).cvss
        }
    }
    
    var result: ResultDelegate?
    
    override func viewDidAppear(_ animated: Bool) {
        updateResult(animated: false)
    }

    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let vc = segue.destination as? ResultViewController {
            result = vc
        }
    }
    
    private func updateResult(animated: Bool) {
        let score = cvss.temporalScore()
        result?.update(
            score: score,
            severity: CVSS.Severity.fromScore(score).description,
            vector: cvss.description,
            animated: animated
        )
    }
    
    @IBAction func exploitCodeMaturityValueChanged(_ sender: UISegmentedControl) {
        cvss.exploitCodeMaturity = CVSS.ExploitCodeMaturity(
            rawValue: sender.selectedSegmentIndex - 1)!
        updateResult(animated: true)
    }
    
    @IBAction func remediationLevelValueChanged(_ sender: UISegmentedControl) {
        cvss.remediationLevel = CVSS.RemediationLevel(
            rawValue: sender.selectedSegmentIndex - 1)!
        updateResult(animated: true)
    }
    
    @IBAction func reportConfidenceValueChanged(_ sender: UISegmentedControl) {
        cvss.reportConfidence = CVSS.ReportConfidence(
            rawValue: sender.selectedSegmentIndex - 1)!
        updateResult(animated: true)
    }
}

