//
//  FirstViewController.swift
//  CVSS
//
//  Created by Anton Prokhorov on 28/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import UIKit

class BaseViewController: UIViewController, FormDelegate {
    
    @IBOutlet weak var attackVector: UISegmentedControl!
    @IBOutlet weak var attackComplexity: UISegmentedControl!
    @IBOutlet weak var privilegeRequired: UISegmentedControl!
    @IBOutlet weak var userInteraction: UISegmentedControl!
    @IBOutlet weak var scope: UISegmentedControl!
    
    @IBOutlet weak var confidentiality: UISegmentedControl!
    @IBOutlet weak var integrity: UISegmentedControl!
    @IBOutlet weak var availavility: UISegmentedControl!
    
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
        updateResultWithPrevious()
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
        attackVector.selectedSegmentIndex = cvss.attackVector.rawValue
        attackComplexity.selectedSegmentIndex = cvss.attackComplexity.rawValue
        privilegeRequired.selectedSegmentIndex = cvss.privilegeRequired.rawValue
        userInteraction.selectedSegmentIndex = cvss.userInteraction.rawValue
        scope.selectedSegmentIndex = cvss.scope.rawValue
        confidentiality.selectedSegmentIndex = cvss.confidentiality.rawValue
        integrity.selectedSegmentIndex = cvss.integrity.rawValue
        availavility.selectedSegmentIndex = cvss.availability.rawValue
    }
    
    func updateResultWithPrevious() {
        let score = previousScore
        result?.updateScore(score, animated: false)
        result?.updateSevirity(CVSS.Severity.fromScore(score).description)
    }
    
    func updateResult() {
        let score = cvss.baseScore()
        result?.updateScore(score, animated: true)
        result?.updateSevirity(CVSS.Severity.fromScore(score).description)
        result?.updateVector(cvss.description)
    }
    
    @IBAction func attackVectorValueChanged(_ sender: UISegmentedControl) {
        cvss.attackVector = CVSS.AttackVector(rawValue: sender.selectedSegmentIndex)!
        updateResult()
    }
    
    @IBAction func attackComplexityValueChanged(_ sender: UISegmentedControl) {
        cvss.attackComplexity = CVSS.AttackComplexity(rawValue: sender.selectedSegmentIndex)!
        updateResult()
    }
    
    @IBAction func privilegeRequiredValueChanged(_ sender: UISegmentedControl) {
        cvss.privilegeRequired = CVSS.PrivilegeRequired(rawValue: sender.selectedSegmentIndex)!
        updateResult()
    }
    
    @IBAction func userInteractionValueChanged(_ sender: UISegmentedControl) {
        cvss.userInteraction = CVSS.UserInteraction(rawValue: sender.selectedSegmentIndex)!
        updateResult()
    }
    
    @IBAction func scopeValueChanged(_ sender: UISegmentedControl) {
        cvss.scope = CVSS.Scope(rawValue: sender.selectedSegmentIndex)!
        updateResult()
    }
    
    @IBAction func confidentialityValueChanged(_ sender: UISegmentedControl) {
        cvss.confidentiality = CVSS.Confidentiality(rawValue: sender.selectedSegmentIndex)!
        updateResult()
    }
    
    @IBAction func integrityValueChanged(_ sender: UISegmentedControl) {
        cvss.integrity = CVSS.Integrity(rawValue: sender.selectedSegmentIndex)!
        updateResult()
    }
    
    @IBAction func availabilityValueChanged(_ sender: UISegmentedControl) {
        cvss.availability = CVSS.Availability(rawValue: sender.selectedSegmentIndex)!
        updateResult()
    }
}

