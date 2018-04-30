//
//  FirstViewController.swift
//  CVSS
//
//  Created by Anton Prokhorov on 28/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import UIKit

class BaseViewController: UIViewController {
    
    @IBOutlet weak var attackVector: UISegmentedControl!
    @IBOutlet weak var attackComplexity: UISegmentedControl!
    @IBOutlet weak var privilegeRequired: UISegmentedControl!
    @IBOutlet weak var userInteraction: UISegmentedControl!
    @IBOutlet weak var scope: UISegmentedControl!
    
    @IBOutlet weak var confidentiality: UISegmentedControl!
    @IBOutlet weak var integrity: UISegmentedControl!
    @IBOutlet weak var availavility: UISegmentedControl!
    
    var result: ResultDelegate?
    
    var cvss: CVSS {
        get {
            return (self.tabBarController as! TabBarViewController).cvss
        }
    }
    
    override func prepare(for segue: UIStoryboardSegue, sender: Any?) {
        if let vc = segue.destination as? ResultViewController {
            result = vc
        }
    }
    
    private func updateResult(animated: Bool) {
        result?.update(score: cvss.score(), severity: cvss.severity().description, animated: animated)
    }
    
    @IBAction func attackVectorValueChanged(_ sender: UISegmentedControl) {
        cvss.attackVector = CVSS.AttackVector(rawValue: sender.selectedSegmentIndex)!
        updateResult()
    }
    
    @IBAction func attackComplexityValueChanged(_ sender: UISegmentedControl) {
        cvss.attackComplexity = CVSS.AttackComplexity(rawValue: sender.selectedSegmentIndex)!
        updateResult(animated: true)
    }
    
    @IBAction func privilegeRequiredValueChanged(_ sender: UISegmentedControl) {
        cvss.privilegeRequired = CVSS.PrivilegeRequired(rawValue: sender.selectedSegmentIndex)!
        updateResult(animated: true)
    }
    
    @IBAction func userInteractionValueChanged(_ sender: UISegmentedControl) {
        cvss.userInteraction = CVSS.UserInteraction(rawValue: sender.selectedSegmentIndex)!
        updateResult(animated: true)
    }
    
    @IBAction func scopeValueChanged(_ sender: UISegmentedControl) {
        cvss.scope = CVSS.Scope(rawValue: sender.selectedSegmentIndex)!
        updateResult(animated: true)
    }
    
    @IBAction func confidentialityValueChanged(_ sender: UISegmentedControl) {
        cvss.confidentiality = CVSS.Confidentiality(rawValue: sender.selectedSegmentIndex)!
        updateResult(animated: true)
    }
    
    @IBAction func integrityValueChanged(_ sender: UISegmentedControl) {
        cvss.integrity = CVSS.Integrity(rawValue: sender.selectedSegmentIndex)!
        updateResult(animated: true)
    }
    
    @IBAction func availabilityValueChanged(_ sender: UISegmentedControl) {
        cvss.availability = CVSS.Availability(rawValue: sender.selectedSegmentIndex)!
        updateResult(animated: true)
    }
}

