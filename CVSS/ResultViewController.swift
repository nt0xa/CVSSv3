//
//  ResultViewController.swift
//  CVSS
//
//  Created by Anton Prokhorov on 29/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import UIKit
import UICircularProgressRing

class ResultViewController: UIViewController, ResultDelegate {
    
    @IBOutlet weak var scoreView: UICircularProgressRingView!
    @IBOutlet weak var severityLabel: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        setupScoreView()
    }
    
    private func setupScoreView() {
        scoreView.ringStyle = .gradient
        scoreView.gradientColorLocations = [0, 0.7, 0.9, 1]
        scoreView.gradientColors = [
            UIColor(red:0.33, green:0.66, blue:0.22, alpha:1.0),
            UIColor(red:0.97, green:0.63, blue:0.16, alpha:1.0),
            UIColor(red:0.80, green:0.09, blue:0.09, alpha:1.0),
            UIColor(red:0.87, green:0.26, blue:0.11, alpha:1.0),
        ]
        scoreView.gradientStartPosition = .bottomLeft
        scoreView.gradientEndPosition = .bottomRight
    }
    
    func update(score: Float, severity: String, animated: Bool) {
        if animated {
            scoreView.setProgress(to: CGFloat(score), duration: 0.4) {
                self.severityLabel.text = severity
            }
        } else {
            scoreView.value = CGFloat(score)
            severityLabel.text = severity
        }
    }
}
