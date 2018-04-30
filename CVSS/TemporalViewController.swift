//
//  SecondViewController.swift
//  CVSS
//
//  Created by Anton Prokhorov on 28/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import UIKit

class TemporalViewController: UIViewController {
    
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
        result?.update(score: cvss.score(), severity: cvss.severity().description, animated: animated)
    }
}

