//
//  ResultViewController.swift
//  CVSS
//
//  Created by Anton Prokhorov on 29/04/2018.
//  Copyright © 2018 Anton Prokhorov. All rights reserved.
//

import UIKit
import UICircularProgressRing
import StatusAlert

class ResultViewController: UIViewController, ResultDelegate {
    
    @IBOutlet weak var scoreView: UICircularProgressRingView!
    @IBOutlet weak var severityLabel: UILabel!
    
    var vector: String?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        setupScoreView()
        setupDoubleTapHandler()
    }
    
    private func setupDoubleTapHandler() {
        let doubleTap = UITapGestureRecognizer(target: self, action: #selector(self.doubleTap))
        doubleTap.numberOfTapsRequired = 2
        view.addGestureRecognizer(doubleTap)
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
    
    func updateScore(_ score: Float, animated: Bool) {
        scoreView.setProgress(to: CGFloat(score), duration: animated ? 0.4 : 0)
    }
    
    func updateSevirity(_ severity: String) {
        severityLabel.text = severity
    }
    
    func updateVector(_ vector: String) {
        self.vector = vector
    }
    
    @objc func doubleTap() {
        let pasteBoard = UIPasteboard.general
        pasteBoard.string = vector ?? ""
        
        let statusAlert = StatusAlert.instantiate(
            withImage: UIImage(named: "check"),
            title: "Copied",
            message: "CVSS vector copied to the clipboard",
            canBePickedOrDismissed: true)
        
        statusAlert.appearance.titleFont = UIFont(name: "SFCompactText-Bold", size: 20.0)!
        statusAlert.appearance.messageFont = UIFont(name: "SFCompactText-Regular", size: 16.0)!

        statusAlert.showInKeyWindow()
    }
}
