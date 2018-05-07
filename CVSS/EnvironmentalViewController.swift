//
//  EnvironmentalViewController.swift
//  CVSS
//
//  Created by Anton Prokhorov on 06/05/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import UIKit

class EnvironmentalViewController: UIViewController, FormDelegate {
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
        confidentialityRequirement.selectedSegmentIndex = (cvss.confidentialityRequirement?.rawValue ?? -1) + 1
        integrityRequirement.selectedSegmentIndex = (cvss.integrityRequirement?.rawValue ?? -1) + 1
        availabilityRequirement.selectedSegmentIndex = (cvss.availabilityRequirement?.rawValue ?? -1) + 1
        modifiedAttackVector.selectedSegmentIndex = (cvss.modifiedAttackVector?.rawValue ?? -1) + 1
        modifiedAttackComplexity.selectedSegmentIndex = (cvss.modifiedAttackComplexity?.rawValue ?? -1) + 1
        modifiedPrivilegeRequired.selectedSegmentIndex = (cvss.modifiedPrivilegeRequired?.rawValue ?? -1) + 1
        modifiedUserInteraction.selectedSegmentIndex = (cvss.modifiedUserInteraction?.rawValue ?? -1) + 1
        modifiedScope.selectedSegmentIndex = (cvss.modifiedScope?.rawValue ?? -1) + 1
        modifiedConfidentiality.selectedSegmentIndex = (cvss.modifiedConfidentiality?.rawValue ?? -1) + 1
        modifiedIntegrity.selectedSegmentIndex = (cvss.modifiedIntegrity?.rawValue ?? -1) + 1
        modifiedAvailavility.selectedSegmentIndex = (cvss.modifiedAvailability?.rawValue ?? -1) + 1
    }
    
    func updateResult() {
        let score = cvss.enviromentalScore()
        result?.update(
            score: score,
            severity: CVSS.Severity.fromScore(score).description,
            vector: cvss.description,
            animated: true
        )
    }
    
    @IBAction func confidentialityRequirementValueChanged(_ sender: UISegmentedControl) {
        cvss.confidentialityRequirement = CVSS.ConfidentialityRequirement(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func integrityRequirementValueChanged(_ sender: UISegmentedControl) {
        cvss.integrityRequirement = CVSS.IntegrityRequirement(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func availabilityRequirementValueChanged(_ sender: UISegmentedControl) {
        cvss.availabilityRequirement = CVSS.AvailabilityRequirement(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func modifiedAttackVectorValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedAttackVector = CVSS.AttackVector(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func modifiedAttackComplexityValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedAttackComplexity = CVSS.AttackComplexity(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func modifiedPrivilegeRequiredValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedPrivilegeRequired = CVSS.PrivilegeRequired(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func modifiedUserInteractionValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedUserInteraction = CVSS.UserInteraction(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func modifiedScopeValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedScope = CVSS.Scope(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func modifiedConfidentialityValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedConfidentiality = CVSS.Confidentiality(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func modifiedIntegrityValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedIntegrity = CVSS.Integrity(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
    
    @IBAction func modifiedAvailabilityValueChanged(_ sender: UISegmentedControl) {
        cvss.modifiedAvailability = CVSS.Availability(rawValue: sender.selectedSegmentIndex - 1)
        updateResult()
    }
}
