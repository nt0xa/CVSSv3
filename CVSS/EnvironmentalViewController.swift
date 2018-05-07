//
//  EnvironmentalViewController.swift
//  CVSS
//
//  Created by Anton Prokhorov on 06/05/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import UIKit

class EnvironmentalViewController: UIViewController {
    @IBOutlet weak var confidentialityRequirement: UISegmentedControl!
    @IBOutlet weak var integrityRequirement: UISegmentedControl!
    @IBOutlet weak var availabilityRequirement: UISegmentedControl!
    
    @IBOutlet weak var modifiedAttackVector: UISegmentedControl!
    @IBOutlet weak var modifiedAttackComplexity: UISegmentedControl!
    @IBOutlet weak var modifiedPrivilegeRequired: UISegmentedControl!
    @IBOutlet weak var modifiedUserInteraction: UISegmentedControl!
    @IBOutlet weak var modifiedScope: UISegmentedControl!
    
    @IBOutlet weak var modifiedConfidentiality: UISegmentedControl!
    @IBOutlet weak var modifiedIntegrity: UISegmentedControl!
    @IBOutlet weak var modifiedAvailavility: UISegmentedControl!
    
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
        let score = cvss.enviromentalScore()
        result?.update(
            score: score,
            severity: CVSS.Severity.fromScore(score).description,
            vector: cvss.description,
            animated: animated
        )
    }
    
    @IBAction func confidentialityRequirementValueChanged(_ sender: UISegmentedControl) {
        cvss.confidentialityRequirement = CVSS.ConfidentialityRequirement(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
    
    @IBAction func integrityRequirementValueChanged(_ sender: UISegmentedControl) {
        cvss.integrityRequirement = CVSS.IntegrityRequirement(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
    
    @IBAction func availabilityRequirementValueChanged(_ sender: UISegmentedControl) {
        cvss.availabilityRequirement = CVSS.AvailabilityRequirement(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
    
    @IBAction func modifiedAttackVectorValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedAttackVector = CVSS.AttackVector(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
    
    @IBAction func modifiedAttackComplexityValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedAttackComplexity = CVSS.AttackComplexity(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
    
    @IBAction func modifiedPrivilegeRequiredValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedPrivilegeRequired = CVSS.PrivilegeRequired(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
    
    @IBAction func modifiedUserInteractionValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedUserInteraction = CVSS.UserInteraction(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
    
    @IBAction func modifiedScopeValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedScope = CVSS.Scope(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
    
    @IBAction func modifiedConfidentialityValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedConfidentiality = CVSS.Confidentiality(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
    
    @IBAction func modifiedIntegrityValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedIntegrity = CVSS.Integrity(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
    
    @IBAction func modifiedAvailabilityValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedAvailability = CVSS.Availability(rawValue: sender.selectedSegmentIndex - 1)
        updateResult(animated: true)
    }
}
